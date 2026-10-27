package store

// The mesh surface, re-exported from store/mesh.
//
// The mesh persistence boundary lives in internal/control/store/mesh: devices,
// enrollment keys, subnet routes and their events. The types and codes below
// are the ones the HTTP layer already names.

import (
	storemesh "github.com/wingsky-1/MeshMux/internal/control/store/mesh"
)

// MeshDeviceRecord is one stored mesh device plus its audit fields.
type MeshDeviceRecord = storemesh.MeshDeviceRecord

// MeshEnrollmentKeyRecord is the persisted view of one one-time enrollment key.
type MeshEnrollmentKeyRecord = storemesh.MeshEnrollmentKeyRecord

// MeshRouteRecord is one stored subnet route.
type MeshRouteRecord = storemesh.MeshRouteRecord

// MeshRouteObservation is one observed route state reported by the Agent.
type MeshRouteObservation = storemesh.MeshRouteObservation

// MeshError builds a mesh refusal with its stable code.
func MeshError(code, detail string) error { return storemesh.MeshError(code, detail) }

// Route event kinds recorded by the audit trail.
const (
	RouteEventDeclared  = storemesh.RouteEventDeclared
	RouteEventApproved  = storemesh.RouteEventApproved
	RouteEventWithdrawn = storemesh.RouteEventWithdrawn
	RouteEventRevoked   = storemesh.RouteEventRevoked
)

// Mesh codes whose literal lives in the mesh package.
var (
	CodeMeshDeviceNotFound        = storemesh.CodeMeshDeviceNotFound
	CodeMeshDeviceCorrupt         = storemesh.CodeMeshDeviceCorrupt
	CodeMeshEnrollmentKeyNotFound = storemesh.CodeMeshEnrollmentKeyNotFound
	CodeMeshRouteConflict         = storemesh.CodeMeshRouteConflict
	CodeMeshRouteNotFound         = storemesh.CodeMeshRouteNotFound
	CodeMeshRouteCorrupt          = storemesh.CodeMeshRouteCorrupt
	CodeMeshRouteUntracked        = storemesh.CodeMeshRouteUntracked
)
