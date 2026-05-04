package main

import (
	"fmt"
	"sprout/pkg/roles"
	"sprout/pkg/ui"
)

const rolesDBPath = "data/roles.db"

func main() {
	rs, err := roles.NewRoleStore(rolesDBPath, false)
	if err != nil {
		fmt.Printf("Error abriendo roles.db: %v\n", err)
		return
	}
	defer rs.Close()

	for {
		ui.ClearScreen()
		opcion := ui.PrintMenu("=== Sprout Admin ===", []string{
			"Listar roles",
			"Crear rol",
			"Eliminar rol",
			"Asignar rol a usuario",
			"Quitar rol a usuario",
			"Ver roles de un usuario",
			"Salir",
		})

		switch opcion {
		case 1:
			listarRoles(rs)
		case 2:
			crearRol(rs)
		case 3:
			eliminarRol(rs)
		case 4:
			asignarRol(rs)
		case 5:
			quitarRol(rs)
		case 6:
			verRolesUsuario(rs)
		case 7:
			fmt.Println("Saliendo...")
			return
		}
	}

}

func listarRoles(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	list, err := rs.ListRoles()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if len(list) == 0 {
		fmt.Println("No hay roles.")
		return
	}
	for _, r := range list {
		fmt.Printf("  - %s\n", r.Name)
	}
}

func crearRol(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	nombre := ui.ReadInput("Nombre del rol: ")
	if err := rs.CreateRole(nombre); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Rol '%s' creado.\n", nombre)
}

func eliminarRol(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	nombre := ui.ReadInput("Nombre del rol a eliminar: ")
	if err := rs.DeleteRole(nombre); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Rol '%s' eliminado.\n", nombre)
}

func asignarRol(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	usuario := ui.ReadInput("Nombre de usuario: ")
	rol := ui.ReadInput("Rol a asignar: ")
	if err := rs.AssignRole(usuario, rol); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Rol '%s' asignado a '%s'.\n", rol, usuario)
}

func quitarRol(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	usuario := ui.ReadInput("Nombre de usuario: ")
	rol := ui.ReadInput("Rol a quitar: ")
	if err := rs.RemoveRole(usuario, rol); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Rol '%s' quitado a '%s'.\n", rol, usuario)
}

func verRolesUsuario(rs *roles.RoleStore) {
	defer ui.Pause("Pulsa Enter para continuar...")
	usuario := ui.ReadInput("Nombre de usuario: ")
	list, err := rs.GetUserRoles(usuario)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if len(list) == 0 {
		fmt.Printf("'%s' no tiene roles asignados.\n", usuario)
		return
	}
	fmt.Printf("Roles de '%s':\n", usuario)
	for _, r := range list {
		fmt.Printf("  - %s\n", r)
	}
}
