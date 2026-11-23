package main

import "github.com/Breaktroughf1/lockward/internal/snapshot"

func snapshotStore() (*snapshot.Store, error) { return snapshot.Default() }
