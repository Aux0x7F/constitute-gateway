.PHONY: snap snap-ci

snap:
	snapcraft --use-lxd

snap-ci:
	snapcraft --destructive-mode
