# openshell-container-runtime

Code used only by the desktop compute drivers (Docker, Podman, and VM). It
moves with those drivers when they leave this repository. Code that the
gateway, supervisor, or Kubernetes driver also uses does not belong here.

## Contents

- `podman_socket`: Podman API socket discovery for native and machine-backed
  installations.
