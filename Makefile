.PHONY: snap snap-ci

SNAP_PROJECT_DIR := snap

snap:
	snapcraft --use-lxd --project-dir $(SNAP_PROJECT_DIR)

snap-ci:
	snapcraft --destructive-mode --project-dir $(SNAP_PROJECT_DIR)