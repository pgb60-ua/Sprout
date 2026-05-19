package server

import (
	"sprout/pkg/api"
	"sprout/pkg/roles"
)

// Helper para autorizacion
func (s *server) requireRole(req api.Request, role string) bool {
	if !s.isTokenValid(req.Username, req.Token) {
		return false
	}
	ok, err := s.roles.HasRole(req.Username, role)
	if err != nil || !ok {
		return false
	}
	return true
}

// Handlers
func (s *server) assignRole(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	if req.TargetUser == "" || req.Role == "" {
		return api.Response{Success: false, Message: "Faltan campos obligatorios"}
	}
	if err := s.roles.AssignRole(req.TargetUser, req.Role); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	return api.Response{Success: true, Message: "Rol asignado"}
}

func (s *server) removeRole(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	if req.TargetUser == "" || req.Role == "" {
		return api.Response{Success: false, Message: "Faltan campos obligatorios"}
	}

	if err := s.roles.RemoveRole(req.TargetUser, req.Role); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	return api.Response{Success: true, Message: "Rol eliminado"}
}

func (s *server) listRoles(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	list, err := s.roles.ListRoles()
	if err != nil {
		return api.Response{Success: false, Message: "Error al listar roles"}
	}
	names := make([]string, len(list))
	for i, r := range list {
		names[i] = r.Name
	}
	return api.Response{Success: true, Roles: names}
}

func (s *server) getUserRoles(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	userRoles, err := s.roles.GetUserRoles(req.TargetUser)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener roles"}
	}
	return api.Response{Success: true, Roles: userRoles}
}

func (s *server) createRole(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	if req.Role == "" {
		return api.Response{Success: false, Message: "Faltan campos obligatorios"}
	}
	if err := s.roles.CreateRole(req.Role); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	return api.Response{Success: true, Message: "Rol creado"}
}

func (s *server) deleteRole(req api.Request) api.Response {
	if !s.requireRole(req, roles.AdminRole) {
		return api.Response{Success: false, Message: "No autorizado"}
	}
	if req.Role == "" {
		return api.Response{Success: false, Message: "Faltan campos obligatorios"}
	}
	if err := s.roles.DeleteRole(req.Role); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	return api.Response{Success: true, Message: "Rol eliminado"}
}
