## Referencias

<!-- Añade las referencias de esta PR -->
<!-- Closes #issue -->

## Descripción

<!-- Añade una descripcion que resuma la PR -->

## Tipo de cambio

- [x] Nueva funcionalidad
- [ ] Corrección de bug
- [ ] Seguridad
- [ ] Refactor

## Checklist

- [x] El servidor arranca sin errores (`go run main.go`)
- [x] He probado el flujo completo (registro → login → operación → logout)
- [x] No hay contraseñas ni secretos hardcodeados

## Revisión

### Revisores

<!-- Añade los revisores que deben aprobar este PR -->
<!--   - @usuario1 -->

## Checklist de revisión

- [ ] El código compila sin errores (`go build ./...`)
- [ ] Los tests pasan (`go test ./...`)
- [ ] No hay contraseñas ni secretos hardcodeados
- [ ] Los errores se manejan correctamente (no hay `_` ignorando errores importantes)
- [ ] Las funciones nuevas son coherentes con el estilo del resto del proyecto
- [ ] No se exponen endpoints innecesarios
- [ ] He probado el flujo manualmente
