// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GraphQL-over-HTTP L7 inspection.

use crate::l7::provider::{L7Provider, L7Request};
use apollo_parser::Parser;
use apollo_parser::cst;
use miette::{Result, miette};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncWrite};

pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_FIELD_OCCURRENCES: usize = 4096;
const MAX_SELECTION_DEPTH: usize = 128;
// Bound all materialized selection facts across an entire HTTP batch.
const MAX_FIELD_FACT_BYTES: usize = 256 * 1024;

struct FieldFactBudget {
    remaining: usize,
    exceeded: bool,
}

impl FieldFactBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_FIELD_FACT_BYTES,
            exceeded: false,
        }
    }

    fn charge(&mut self, bytes: usize) -> Option<()> {
        let Some(remaining) = self.remaining.checked_sub(bytes) else {
            self.remaining = 0;
            self.exceeded = true;
            return None;
        };
        self.remaining = remaining;
        Some(())
    }

    fn charge_json(&mut self, value: &Value) -> Option<()> {
        self.charge(24)?;
        match value {
            Value::String(value) => self.charge(value.len()),
            Value::Array(values) => {
                for value in values {
                    self.charge_json(value)?;
                }
                Some(())
            }
            Value::Object(object) => {
                for (key, value) in object {
                    self.charge(48 + key.len())?;
                    self.charge_json(value)?;
                }
                Some(())
            }
            _ => Some(()),
        }
    }
}

pub use openshell_policy_runtime_interface::l7::graphql::*;

pub struct GraphqlHttpRequest {
    pub request: L7Request,
    pub info: GraphqlRequestInfo,
}

pub(crate) fn log_summary(info: &GraphqlRequestInfo) -> String {
    if let Some(error) = &info.error {
        return format!("graphql_error={error:?}");
    }
    let operations = info.operations.iter().map(|operation| {
        let name = operation.operation_name.as_deref().unwrap_or("-");
        let fields = if operation.fields.is_empty() {
            "-".to_string()
        } else {
            operation.fields.join(",")
        };
        let persisted = operation
            .persisted_query_hash
            .as_deref()
            .or(operation.persisted_query_id.as_deref())
            .unwrap_or("-");
        format!(
            "type={} name={} fields={} persisted={}",
            operation.operation_type, name, fields, persisted
        )
    });
    format!("graphql_ops={}", operations.collect::<Vec<_>>().join(";"))
}

pub async fn parse_graphql_http_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut C,
    max_body_bytes: usize,
    canonicalize_options: crate::l7::path::CanonicalizeOptions,
) -> Result<Option<GraphqlHttpRequest>> {
    let provider = crate::l7::rest::RestProvider::with_options(canonicalize_options);
    let Some(mut request) = provider.parse_request(client).await? else {
        return Ok(None);
    };

    let info = inspect_graphql_request(client, &mut request, max_body_bytes).await?;

    Ok(Some(GraphqlHttpRequest { request, info }))
}

pub(crate) async fn inspect_graphql_request<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    max_body_bytes: usize,
) -> Result<GraphqlRequestInfo> {
    let header_str = header_str(request)?;
    reject_unsupported_headers(header_str)?;
    let body = crate::l7::http::read_body_for_inspection(client, request, max_body_bytes).await?;
    Ok(classify_request(request, &body))
}

pub fn classify_request(request: &L7Request, body: &[u8]) -> GraphqlRequestInfo {
    match classify_request_inner(request, body) {
        Ok(operations) => GraphqlRequestInfo {
            operations,
            error: None,
        },
        Err(err) => GraphqlRequestInfo {
            operations: Vec::new(),
            error: Some(err),
        },
    }
}

pub fn classify_json_envelope_value(value: &Value) -> GraphqlRequestInfo {
    match classify_json_envelope(value, None) {
        Ok(operations) => GraphqlRequestInfo {
            operations,
            error: None,
        },
        Err(err) => GraphqlRequestInfo {
            operations: Vec::new(),
            error: Some(err),
        },
    }
}

fn classify_request_inner(
    request: &L7Request,
    body: &[u8],
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let mut budget = FieldFactBudget::new();
    match request.action.to_ascii_uppercase().as_str() {
        "GET" => classify_get(request, &mut budget),
        "POST" => classify_post(body, &mut budget),
        method => Err(format!("unsupported GraphQL HTTP method {method}")),
    }
}

fn classify_get(
    request: &L7Request,
    budget: &mut FieldFactBudget,
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let query = unique_query_value(&request.query_params, "query")?;
    let operation_name = unique_query_value(&request.query_params, "operationName")?;
    let extensions = unique_query_value(&request.query_params, "extensions")?
        .map(|raw| {
            crate::l7::jsonrpc::parse_unique_json_value(raw.as_bytes()).map_err(|_| {
                "GraphQL GET extensions are invalid or contain duplicate JSON keys".to_string()
            })
        })
        .transpose()?;
    let id = unique_persisted_query_id(&request.query_params)?;
    let persisted_marker = ["id", "documentId", "queryId"]
        .iter()
        .any(|key| request.query_params.contains_key(*key))
        || extensions.as_ref().is_some_and(has_persisted_marker)
        || (request.query_params.contains_key("extensions") && extensions.is_none());
    let variables = match request.query_params.get("variables") {
        None => Some(Value::Object(Map::new())),
        Some(values) if values.len() == 1 => {
            crate::l7::jsonrpc::parse_unique_json_value(values[0].as_bytes()).ok()
        }
        Some(_) => None,
    };

    classify_envelope(
        query.as_deref(),
        operation_name.as_deref(),
        variables.as_ref().and_then(Value::as_object),
        extensions.as_ref(),
        id,
        persisted_marker,
        Some(budget),
    )
}

fn classify_post(
    body: &[u8],
    budget: &mut FieldFactBudget,
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    if body.is_empty() {
        return Err("GraphQL POST body is empty".to_string());
    }
    let value = crate::l7::jsonrpc::parse_unique_json_value(body).map_err(|_| {
        "GraphQL request body is invalid or contains duplicate JSON keys".to_string()
    })?;

    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Err("GraphQL batch request is empty".to_string());
            }
            let mut operations = Vec::new();
            for item in items {
                operations.extend(classify_json_envelope(&item, Some(&mut *budget))?);
            }
            Ok(operations)
        }
        Value::Object(_) => classify_json_envelope(&value, Some(budget)),
        _ => Err("GraphQL JSON envelope must be an object or array".to_string()),
    }
}

fn classify_json_envelope(
    value: &Value,
    budget: Option<&mut FieldFactBudget>,
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "GraphQL batch item must be an object".to_string())?;
    let query = obj.get("query").and_then(Value::as_str);
    let operation_name = obj.get("operationName").and_then(Value::as_str);
    let extensions = obj.get("extensions");
    let empty_variables = Map::new();
    let variables = match obj.get("variables") {
        None => Some(&empty_variables),
        Some(value) => value.as_object(),
    };
    let id = obj
        .get("id")
        .or_else(|| obj.get("documentId"))
        .or_else(|| obj.get("queryId"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let persisted_marker = ["id", "documentId", "queryId"]
        .iter()
        .any(|key| obj.contains_key(*key))
        || extensions.is_some_and(has_persisted_marker);

    classify_envelope(
        query,
        operation_name,
        variables,
        extensions,
        id,
        persisted_marker,
        budget,
    )
}

fn has_persisted_marker(extensions: &Value) -> bool {
    extensions
        .as_object()
        .is_none_or(|extensions| extensions.contains_key("persistedQuery"))
}

fn classify_envelope(
    query: Option<&str>,
    operation_name: Option<&str>,
    variables: Option<&Map<String, Value>>,
    extensions: Option<&Value>,
    persisted_id: Option<String>,
    persisted_marker: bool,
    budget: Option<&mut FieldFactBudget>,
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let persisted_hash = persisted_query_hash(extensions);
    let query = query.filter(|q| !q.trim().is_empty());

    if let Some(query) = query {
        let mut operation = classify_document(
            query,
            operation_name,
            variables.filter(|_| !persisted_marker),
            budget,
        )?;
        if let Some(hash) = persisted_hash {
            operation.persisted_query = true;
            operation.persisted_query_hash = Some(hash);
            operation.field_occurrences = None;
        }
        if let Some(id) = persisted_id {
            operation.persisted_query = true;
            operation.persisted_query_id = Some(id);
            operation.field_occurrences = None;
        }
        return Ok(vec![operation]);
    }

    if persisted_hash.is_some() || persisted_id.is_some() {
        return Ok(vec![GraphqlOperationInfo {
            operation_type: String::new(),
            operation_name: operation_name.map(ToString::to_string),
            fields: Vec::new(),
            field_occurrences: None,
            persisted_query: true,
            persisted_query_hash: persisted_hash,
            persisted_query_id: persisted_id,
        }]);
    }

    Err("GraphQL request has no query document or persisted query identifier".to_string())
}

fn classify_document(
    query: &str,
    operation_name: Option<&str>,
    variables: Option<&Map<String, Value>>,
    budget: Option<&mut FieldFactBudget>,
) -> std::result::Result<GraphqlOperationInfo, String> {
    let parser = Parser::new(query).recursion_limit(128).token_limit(20_000);
    let cst = parser.parse();
    let mut parse_errors = cst.errors();
    if let Some(err) = parse_errors.next() {
        return Err(format!("GraphQL document parse error: {err}"));
    }

    let document = cst.document();
    let mut operations = Vec::new();
    let mut fragments = HashMap::new();
    let mut unique_fragments = true;

    for definition in document.definitions() {
        match definition {
            cst::Definition::OperationDefinition(operation) => operations.push(operation),
            cst::Definition::FragmentDefinition(fragment) => {
                if let Some(name) = fragment.fragment_name().and_then(|n| n.name()) {
                    if fragments
                        .insert(name.text().to_string(), fragment)
                        .is_some()
                    {
                        unique_fragments = false;
                    }
                }
            }
            _ => {}
        }
    }

    if operations.is_empty() {
        return Err("GraphQL document contains no executable operation".to_string());
    }

    let mut unique_selected_operation = true;
    let selected = if let Some(expected_name) = operation_name.filter(|name| !name.is_empty()) {
        let mut matches = operations.into_iter().filter(|op| {
            op.name()
                .is_some_and(|name| name.text().as_ref() == expected_name)
        });
        let selected = matches
            .next()
            .ok_or_else(|| format!("GraphQL operationName {expected_name:?} was not found"))?;
        unique_selected_operation = matches.next().is_none();
        selected
    } else if operations.len() == 1 {
        operations.remove(0)
    } else {
        return Err("GraphQL document has multiple operations but no operationName".to_string());
    };

    let operation_type = operation_type(&selected);
    let operation_name = selected.name().map(|name| name.text().to_string());
    let selection_set = selected
        .selection_set()
        .ok_or_else(|| "GraphQL operation has no selection set".to_string())?;
    let mut fields = HashSet::new();
    let mut visited_fragments = HashSet::new();
    collect_root_fields(
        selection_set.clone(),
        &fragments,
        &mut visited_fragments,
        &mut fields,
    );
    let mut fields: Vec<_> = fields.into_iter().collect();
    fields.sort();
    let field_occurrences = budget
        .zip(variables)
        .filter(|_| unique_fragments && unique_selected_operation)
        .and_then(|(budget, variables)| {
            let variables = resolved_variables(&selected, variables, budget)?;
            let mut collector = FieldCollector {
                fragments: &fragments,
                variables: &variables,
                active_fragments: HashSet::new(),
                occurrences: Vec::new(),
                budget,
            };
            collector.collect(selection_set, "", 0)?;
            Some(collector.occurrences)
        });

    Ok(GraphqlOperationInfo {
        operation_type,
        operation_name,
        fields,
        field_occurrences,
        persisted_query: false,
        persisted_query_hash: None,
        persisted_query_id: None,
    })
}

fn resolved_variables(
    operation: &cst::OperationDefinition,
    supplied: &Map<String, Value>,
    budget: &mut FieldFactBudget,
) -> Option<Map<String, Value>> {
    let mut resolved = Map::new();
    let mut names = HashSet::new();
    if let Some(definitions) = operation.variable_definitions() {
        for definition in definitions.variable_definitions() {
            let name = definition.variable()?.name()?.text().to_string();
            if !names.insert(name.clone()) {
                return None;
            }
            let value = if let Some(value) = supplied.get(&name) {
                budget.charge_json(value)?;
                Some(value.clone())
            } else {
                definition
                    .default_value()
                    .and_then(|default| default.value())
                    .and_then(|value| resolve_value(value, &Map::new(), budget))
            };
            if let Some(value) = value {
                budget.charge(48 + name.len())?;
                resolved.insert(name, value);
            }
        }
    }
    if budget.exceeded {
        return None;
    }
    Some(resolved)
}

fn resolve_value(
    value: cst::Value,
    variables: &Map<String, Value>,
    budget: &mut FieldFactBudget,
) -> Option<Value> {
    match value {
        cst::Value::Variable(variable) => {
            let value = variables.get(&variable.name()?.text().to_string())?;
            budget.charge_json(value)?;
            Some(value.clone())
        }
        cst::Value::StringValue(value) => {
            let value = String::from(value);
            budget.charge(24 + value.len())?;
            Some(Value::String(value))
        }
        cst::Value::IntValue(value) => {
            budget.charge(24)?;
            serde_json::from_str(value.int_token()?.text()).ok()
        }
        cst::Value::FloatValue(value) => {
            budget.charge(24)?;
            serde_json::from_str(value.float_token()?.text()).ok()
        }
        cst::Value::BooleanValue(value) => {
            budget.charge(24)?;
            Some(Value::Bool(value.true_token().is_some()))
        }
        // Enum literals are distinct from strings. The string matcher treats
        // both enum and null literals as non-string values.
        cst::Value::EnumValue(_) | cst::Value::NullValue(_) => {
            budget.charge(24)?;
            Some(Value::Null)
        }
        cst::Value::ListValue(value) => {
            budget.charge(24)?;
            value
                .values()
                .map(|value| resolve_value(value, variables, budget))
                .collect::<Option<Vec<_>>>()
                .map(Value::Array)
        }
        cst::Value::ObjectValue(value) => {
            budget.charge(24)?;
            let mut object = Map::new();
            for field in value.object_fields() {
                let name = field.name()?.text().to_string();
                budget.charge(48 + name.len())?;
                let value = resolve_value(field.value()?, variables, budget)?;
                if object.insert(name, value).is_some() {
                    return None;
                }
            }
            Some(Value::Object(object))
        }
    }
}

struct FieldCollector<'a> {
    fragments: &'a HashMap<String, cst::FragmentDefinition>,
    variables: &'a Map<String, Value>,
    active_fragments: HashSet<String>,
    occurrences: Vec<GraphqlFieldOccurrence>,
    budget: &'a mut FieldFactBudget,
}

impl FieldCollector<'_> {
    fn collect(
        &mut self,
        selection_set: cst::SelectionSet,
        parent: &str,
        depth: usize,
    ) -> Option<()> {
        if depth > MAX_SELECTION_DEPTH {
            return None;
        }
        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    if self.occurrences.len() >= MAX_FIELD_OCCURRENCES {
                        return None;
                    }
                    let name = field.name()?.text().to_string();
                    self.budget
                        .charge(64 + parent.len() + usize::from(!parent.is_empty()) + name.len())?;
                    let path = if parent.is_empty() {
                        name
                    } else {
                        format!("{parent}.{name}")
                    };
                    let mut arguments = Map::new();
                    let mut names = HashSet::new();
                    if let Some(field_arguments) = field.arguments() {
                        for argument in field_arguments.arguments() {
                            let name = argument.name()?.text().to_string();
                            if !names.insert(name.clone()) {
                                return None;
                            }
                            self.budget.charge(48 + name.len())?;
                            if let Some(value) =
                                resolve_value(argument.value()?, self.variables, self.budget)
                            {
                                arguments.insert(name, value);
                            }
                            if self.budget.exceeded {
                                return None;
                            }
                        }
                    }
                    self.occurrences.push(GraphqlFieldOccurrence {
                        path: path.clone(),
                        arguments,
                    });
                    if let Some(children) = field.selection_set() {
                        self.collect(children, &path, depth + 1)?;
                    }
                }
                cst::Selection::InlineFragment(fragment) => {
                    self.collect(fragment.selection_set()?, parent, depth + 1)?;
                }
                cst::Selection::FragmentSpread(spread) => {
                    let name = spread.fragment_name()?.name()?.text().to_string();
                    if !self.active_fragments.insert(name.clone()) {
                        return None;
                    }
                    let fragment = self.fragments.get(&name)?.clone();
                    self.collect(fragment.selection_set()?, parent, depth + 1)?;
                    self.active_fragments.remove(&name);
                }
            }
        }
        Some(())
    }
}

fn operation_type(operation: &cst::OperationDefinition) -> String {
    let Some(operation_type) = operation.operation_type() else {
        return "query".to_string();
    };
    if operation_type.mutation_token().is_some() {
        "mutation".to_string()
    } else if operation_type.subscription_token().is_some() {
        "subscription".to_string()
    } else {
        "query".to_string()
    }
}

fn collect_root_fields(
    selection_set: cst::SelectionSet,
    fragments: &HashMap<String, cst::FragmentDefinition>,
    visited_fragments: &mut HashSet<String>,
    fields: &mut HashSet<String>,
) {
    for selection in selection_set.selections() {
        match selection {
            cst::Selection::Field(field) => {
                if let Some(name) = field.name() {
                    fields.insert(name.text().to_string());
                }
            }
            cst::Selection::InlineFragment(fragment) => {
                if let Some(selection_set) = fragment.selection_set() {
                    collect_root_fields(selection_set, fragments, visited_fragments, fields);
                }
            }
            cst::Selection::FragmentSpread(spread) => {
                let Some(name) = spread.fragment_name().and_then(|n| n.name()) else {
                    continue;
                };
                let name = name.text().to_string();
                if !visited_fragments.insert(name.clone()) {
                    continue;
                }
                if let Some(fragment) = fragments.get(&name)
                    && let Some(selection_set) = fragment.selection_set()
                {
                    collect_root_fields(selection_set, fragments, visited_fragments, fields);
                }
            }
        }
    }
}

fn persisted_query_hash(extensions: Option<&Value>) -> Option<String> {
    extensions?
        .get("persistedQuery")?
        .get("sha256Hash")?
        .as_str()
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
}

fn unique_query_value(
    params: &HashMap<String, Vec<String>>,
    key: &str,
) -> std::result::Result<Option<String>, String> {
    let Some(values) = params.get(key) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(format!(
            "GraphQL GET parameter {key:?} must not appear more than once"
        ));
    }
    Ok(values.first().filter(|value| !value.is_empty()).cloned())
}

fn unique_persisted_query_id(
    params: &HashMap<String, Vec<String>>,
) -> std::result::Result<Option<String>, String> {
    let mut selected: Option<(String, String)> = None;
    for key in ["id", "documentId", "queryId"] {
        let Some(value) = unique_query_value(params, key)? else {
            continue;
        };
        if let Some((existing_key, _)) = selected {
            return Err(format!(
                "GraphQL GET persisted-query id parameters {existing_key:?} and {key:?} must not be combined"
            ));
        }
        selected = Some((key.to_string(), value));
    }
    Ok(selected.map(|(_, value)| value))
}

fn header_str(request: &L7Request) -> Result<&str> {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    std::str::from_utf8(&request.raw_header[..header_end])
        .map_err(|_| miette!("GraphQL HTTP headers contain invalid UTF-8"))
}

fn reject_unsupported_headers(headers: &str) -> Result<()> {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-encoding:") {
            let encoding = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if !encoding.is_empty() && encoding != "identity" {
                return Err(miette!(
                    "GraphQL request content-encoding {encoding:?} is not supported"
                ));
            }
        }
        if lower.starts_with("content-type:") {
            let content_type = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if content_type.starts_with("multipart/") {
                return Err(miette!("GraphQL multipart requests are not supported"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::provider::BodyLength;
    use tokio::io::AsyncReadExt;

    fn request(method: &str, target: &str) -> L7Request {
        L7Request {
            action: method.to_string(),
            target: target.to_string(),
            query_params: crate::l7::rest::parse_target_query(target).unwrap().1,
            raw_header: format!("{method} {target} HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .into_bytes(),
            body_length: BodyLength::None,
        }
    }

    #[test]
    fn classifies_simple_query() {
        let req = request("POST", "/graphql");
        let info = classify_request(&req, br#"{"query":"query Viewer { viewer { login } }"}"#);
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "query");
        assert_eq!(info.operations[0].fields, vec!["viewer"]);
    }

    #[test]
    fn classifies_mutation_field_not_alias() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"mutation M { safeAlias: volumeDelete(volumeId:\"x\") { id } }","operationName":"M"}"#,
        );
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "mutation");
        assert_eq!(info.operations[0].operation_name.as_deref(), Some("M"));
        assert_eq!(info.operations[0].fields, vec!["volumeDelete"]);
    }

    #[test]
    fn expands_root_fragments() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"query Q { ...RootFields } fragment RootFields on Query { viewer repository(owner:\"o\", name:\"r\") { id } }"}"#,
        );
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].fields, vec!["repository", "viewer"]);
    }

    #[test]
    fn resolves_inline_variable_and_default_argument_values() {
        let req = request("POST", "/graphql");
        let inline = classify_request(
            &req,
            br#"{"query":"mutation { createPullRequest(input:{repositoryId:\"R_ONE\", title:\"hi\"}) { pullRequest { id } } }"}"#,
        );
        let variable = classify_request(
            &req,
            br#"{"query":"mutation M($input: CreatePullRequestInput!) { createPullRequest(input:$input) { pullRequest { id } } }","variables":{"input":{"repositoryId":"R_ONE","title":"hi"}}}"#,
        );
        assert_eq!(
            inline.operations[0].field_occurrences,
            variable.operations[0].field_occurrences
        );
        assert_eq!(
            variable.operations[0].field_occurrences.as_ref().unwrap()[0].arguments["input"]["repositoryId"],
            "R_ONE"
        );

        let default = classify_request(
            &req,
            br#"{"query":"query Q($owner: String = \"acme\") { repository(owner:$owner, name:\"one\") { id } }"}"#,
        );
        assert_eq!(
            default.operations[0].field_occurrences.as_ref().unwrap()[0].arguments["owner"],
            "acme"
        );

        let inline_enum = classify_request(
            &req,
            br#"{"query":"mutation { createPullRequest(input:{repositoryId:\"R_ONE\", title:hi}) { pullRequest { id } } }"}"#,
        );
        let input = &inline_enum.operations[0]
            .field_occurrences
            .as_ref()
            .unwrap()[0]
            .arguments["input"];
        assert_eq!(input["repositoryId"], "R_ONE");
        assert!(!input["title"].is_string());
    }

    #[test]
    fn retains_correlated_occurrences_and_expands_reused_fragments() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"query { a: repository(owner:\"allowed\") { ...Repo } b: repository(owner:\"denied\") { ...Repo } } fragment Repo on Repository { id nested { ... on Node { id } } }"}"#,
        );
        let selected = info.operations[0].field_occurrences.as_ref().unwrap();
        let paths: Vec<_> = selected.iter().map(|field| field.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "repository",
                "repository.id",
                "repository.nested",
                "repository.nested.id",
                "repository",
                "repository.id",
                "repository.nested",
                "repository.nested.id"
            ]
        );
        assert_eq!(selected[0].arguments["owner"], "allowed");
        assert_eq!(selected[4].arguments["owner"], "denied");
    }

    #[test]
    fn resolves_get_variables_without_accepting_ambiguous_controls() {
        let req = request(
            "GET",
            "/graphql?query=query+Q(%24owner%3AString!)%7Brepository(owner%3A%24owner)%7Bid%7D%7D&variables=%7B%22owner%22%3A%22acme%22%7D",
        );
        let info = classify_request(&req, b"");
        assert_eq!(
            info.operations[0].field_occurrences.as_ref().unwrap()[0].arguments["owner"],
            "acme"
        );
        let ambiguous = request(
            "GET",
            "/graphql?query=%7Bviewer%7Bid%7D%7D&variables=%7B%7D&variables=%7B%7D",
        );
        let info = classify_request(&ambiguous, b"");
        assert_eq!(info.operations[0].fields, ["viewer"]);
        assert!(info.operations[0].field_occurrences.is_none());
    }

    #[test]
    fn refuses_ambiguous_json_and_withholds_unresolved_field_facts() {
        let req = request("POST", "/graphql");
        let duplicate = classify_request(
            &req,
            br#"{"query":"query Q($owner:String!){repository(owner:$owner){id}}","variables":{"owner":"acme","owner":"other"}}"#,
        );
        assert!(duplicate.error.is_some());

        let malformed = classify_request(&req, br#"{"query":"{viewer{id}}","variables":[]}"#);
        assert_eq!(malformed.operations[0].fields, ["viewer"]);
        assert!(malformed.operations[0].field_occurrences.is_none());

        let missing = classify_request(
            &req,
            br#"{"query":"query Q($owner:String!){repository(owner:$owner){id}}"}"#,
        );
        assert!(
            !missing.operations[0].field_occurrences.as_ref().unwrap()[0]
                .arguments
                .contains_key("owner")
        );
    }

    #[test]
    fn multiple_operations_without_name_errors() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"query A { viewer { login } } query B { rateLimit { limit } }"}"#,
        );
        assert!(info.error.unwrap().contains("multiple operations"));
    }

    #[test]
    fn detects_hash_only_apollo_persisted_query() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"operationName":"Viewer","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}"#,
        );
        assert_eq!(info.error, None);
        let op = &info.operations[0];
        assert!(op.persisted_query);
        assert!(op.field_occurrences.is_none());
        assert_eq!(op.operation_name.as_deref(), Some("Viewer"));
        assert_eq!(op.persisted_query_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn withholds_fine_facts_when_a_persisted_id_and_document_are_both_present() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"{ viewer { login } }","id":"saved-operation"}"#,
        );
        assert_eq!(info.operations[0].fields, ["viewer"]);
        assert!(info.operations[0].field_occurrences.is_none());
    }

    #[test]
    fn withholds_ambiguous_operation_and_persisted_envelope_facts() {
        let req = request("POST", "/graphql");
        for body in [
            br#"{"query":"query Q { viewer { id } } query Q { repository { id } }","operationName":"Q"}"#.as_slice(),
            br#"{"query":"{ viewer { id } }","id":null,"documentId":"saved-operation"}"#.as_slice(),
            br#"{"query":"{ viewer { id } }","extensions":{"persistedQuery":null}}"#.as_slice(),
        ] {
            let info = classify_request(&req, body);
            assert_eq!(info.operations[0].fields, ["viewer"]);
            assert!(info.operations[0].field_occurrences.is_none());
        }

        let req = request(
            "GET",
            "/graphql?query=%7Bviewer%7Bid%7D%7D&extensions=%7B%22persistedQuery%22%3Anull%2C%22persistedQuery%22%3A%7B%22sha256Hash%22%3A%22other%22%7D%7D",
        );
        assert!(classify_request(&req, b"").error.is_some());
    }

    #[test]
    fn bounds_materialized_facts_across_aliases_and_batches() {
        let req = request("POST", "/graphql");
        let query = "query Q($value:String!){a:repository(owner:$value){id} b:repository(owner:$value){id} c:repository(owner:$value){id} d:repository(owner:$value){id} e:repository(owner:$value){id} f:repository(owner:$value){id} g:repository(owner:$value){id} h:repository(owner:$value){id}}";
        let one = serde_json::json!({"query": query, "variables": {"value": "x".repeat(40_000)}});
        let info = classify_request(&req, &serde_json::to_vec(&one).unwrap());
        assert_eq!(info.operations[0].fields, ["repository"]);
        assert!(info.operations[0].field_occurrences.is_none());

        let item = serde_json::json!({"query": query, "variables": {"value": "x".repeat(4_000)}});
        let batch = serde_json::to_vec(&vec![item; 8]).unwrap();
        assert!(batch.len() < DEFAULT_MAX_BODY_BYTES);
        let info = classify_request(&req, &batch);
        assert!(info.operations[0].field_occurrences.is_some());
        assert_eq!(info.operations[7].fields, ["repository"]);
        assert!(info.operations[7].field_occurrences.is_none());
    }

    #[test]
    fn graphql_get_rejects_duplicate_query_parameter() {
        let req = request(
            "GET",
            "/graphql?query=query+Viewer+%7B+viewer+%7B+login+%7D+%7D&query=mutation+Delete+%7B+volumeDelete(volumeId%3A%22x%22)+%7B+id+%7D+%7D",
        );
        let info = classify_request(&req, b"");
        assert!(
            info.error
                .as_deref()
                .is_some_and(|err| err.contains("must not appear more than once")),
            "expected duplicate control parameter error, got {info:?}"
        );
    }

    #[test]
    fn graphql_get_rejects_ambiguous_persisted_query_ids() {
        let req = request("GET", "/graphql?id=one&queryId=two");
        let info = classify_request(&req, b"");
        assert!(
            info.error
                .as_deref()
                .is_some_and(|err| err.contains("must not be combined")),
            "expected ambiguous persisted-query id error, got {info:?}"
        );
    }

    #[tokio::test]
    async fn chunked_graphql_preserves_pipelined_request() {
        use tokio::io::{AsyncWriteExt, BufReader};

        let body = r#"{"query":"query Viewer { viewer { login } }"}"#;
        let next = "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        for capacity in [1, 8192] {
            for trailers in ["", "X-Sig: ignored\r\n"] {
                let wire = format!(
                    "POST /graphql HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x};ext=yes\r\n{body}\r\n0\r\n{trailers}\r\n{next}",
                    body.len()
                );
                let (mut sender, receiver) = tokio::io::duplex(8192);
                sender.write_all(wire.as_bytes()).await.unwrap();
                sender.shutdown().await.unwrap();
                // A one-byte buffer splits every CRLF; a large buffer makes
                // the complete next request available during body inspection.
                let mut reader = BufReader::with_capacity(capacity, receiver);
                let parsed = parse_graphql_http_request(
                    &mut reader,
                    DEFAULT_MAX_BODY_BYTES,
                    crate::l7::path::CanonicalizeOptions::default(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(parsed.info.error, None);
                assert_eq!(parsed.info.operations[0].fields, ["viewer"]);
                let mut remaining = String::new();
                reader.read_to_string(&mut remaining).await.unwrap();
                assert_eq!(
                    remaining, next,
                    "GraphQL inspection consumed the next request"
                );
            }
        }
    }

    #[tokio::test]
    async fn graphql_inspection_preserves_configured_body_limit() {
        let body = br#"{"query":"query { viewer }"}"#;
        for chunked in [false, true] {
            let mut req = request("POST", "/graphql");
            let wire = if chunked {
                req.body_length = BodyLength::Chunked;
                format!(
                    "{:x}\r\n{}\r\n0\r\n\r\n",
                    body.len(),
                    std::str::from_utf8(body).unwrap()
                )
                .into_bytes()
            } else {
                req.body_length = BodyLength::ContentLength(body.len() as u64);
                body.to_vec()
            };
            let error = inspect_graphql_request(&mut wire.as_slice(), &mut req, body.len() - 1)
                .await
                .expect_err("the configured body limit must apply to either HTTP framing");
            assert!(error.to_string().contains("inspection limit"));
        }
    }

    #[tokio::test]
    async fn chunked_graphql_post_is_normalized_after_inspection() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST /graphql HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sig\r\nX-Test: yes\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\nX-Sig: ignored\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();

        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("chunked body should inspect");

        assert_eq!(info.error, None);
        assert!(matches!(
            req.body_length,
            BodyLength::ContentLength(len) if len == body.len() as u64
        ));
        let forwarded = String::from_utf8_lossy(&req.raw_header);
        assert!(forwarded.contains(&format!("Content-Length: {}", body.len())));
        assert!(forwarded.contains("X-Test: yes\r\n"));
        assert!(!forwarded.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!forwarded.to_ascii_lowercase().contains("trailer:"));
        assert!(req.raw_header.ends_with(body));
    }

    #[tokio::test]
    async fn absolute_form_chunked_graphql_post_classifies_after_inspection() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST http://example.com/graphql HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();

        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("absolute-form chunked body should inspect");

        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "query");
        assert_eq!(info.operations[0].fields, vec!["viewer"]);
    }

    #[tokio::test]
    async fn absolute_form_chunked_graphql_post_is_allowed_by_field_policy() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST http://host.openshell.internal:8080/graphql HTTP/1.1\r\nHost: host.openshell.internal:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();
        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("chunked body should inspect");

        let data = r"
network_policies:
  test_graphql_l7:
    name: test_graphql_l7
    endpoints:
      - host: host.openshell.internal
        port: 8080
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: mutation
              fields: [createIssue]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = crate::opa::OpaEngine::from_strings(
            include_str!("../../data/sandbox-policy.rego"),
            data,
        )
        .expect("policy should load");
        let ctx = crate::l7::relay::L7EvalContext {
            host: "host.openshell.internal".to_string(),
            port: 8080,
            policy_name: "test_graphql_l7".to_string(),
            binary_path: "/usr/bin/python3".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            ..Default::default()
        };
        let request_info = crate::l7::L7RequestInfo {
            action: req.action,
            target: req.target,
            query_params: req.query_params,
            graphql: Some(info),
            jsonrpc: None,
        };

        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .expect("tunnel engine should clone");
        let (allowed, reason) =
            crate::l7::relay::evaluate_l7_request(&tunnel_engine, &ctx, &request_info)
                .expect("evaluation should complete");

        assert!(allowed, "expected query to be allowed, got {reason}");
    }
}
