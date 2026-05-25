package server

import (
	"os"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/utils"
)

const (
	maxFileCommentBytes    = 4096
	maxFileCommentsPerFile = 100
)

func (s *server) loadCommentableFileMetadata(req api.Request) (api.FileMetadata, fileAccessContext, errorResponse) {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}}
	}
	if req.Path == "" {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{api.Response{Success: false, Message: "Falta el path del fichero o directorio"}}
	}

	ctx, err := s.resolveFileAccessContext(req.Username, req.Path)
	if err != nil {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{api.Response{Success: false, Message: err.Error()}}
	}
	info, err := os.Stat(ctx.absPath)
	if err != nil {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{api.Response{Success: false, Message: "El fichero o directorio no existe"}}
	}
	if perm := s.requirePathPermissionForContext(req.Username, ctx, req.Path, true, 'r', info); !perm.Success {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{perm}
	}
	meta, err := s.ensureFileMetadata(ctx.storageUser, ctx.baseDEK, req.Path, info)
	if err != nil {
		return api.FileMetadata{}, fileAccessContext{}, errorResponse{api.Response{Success: false, Message: "Error al obtener metadatos"}}
	}
	return meta, ctx, errorResponse{}
}

type errorResponse struct {
	response api.Response
}

func (e errorResponse) failed() bool {
	return e.response.Message != "" || e.response.SessionExpired
}

func (s *server) listFileComments(req api.Request) api.Response {
	meta, _, errRes := s.loadCommentableFileMetadata(req)
	if errRes.failed() {
		return errRes.response
	}
	return api.Response{Success: true, Message: "Comentarios obtenidos", FileMetadata: &meta}
}

func (s *server) addFileComment(req api.Request) api.Response {
	text := strings.TrimSpace(req.CommentText)
	if text == "" {
		return api.Response{Success: false, Message: "El comentario no puede estar vacio"}
	}
	if len([]byte(text)) > maxFileCommentBytes {
		return api.Response{Success: false, Message: "El comentario supera el tamano maximo permitido"}
	}

	meta, ctx, errRes := s.loadCommentableFileMetadata(req)
	if errRes.failed() {
		return errRes.response
	}
	if len(meta.Comments) >= maxFileCommentsPerFile {
		return api.Response{Success: false, Message: "Se ha alcanzado el numero maximo de comentarios para esta ruta"}
	}
	id, err := utils.NewRandomToken(12)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar identificador del comentario"}
	}
	meta.Comments = append(meta.Comments, api.FileComment{
		ID:        id,
		Author:    req.Username,
		Text:      text,
		CreatedAt: time.Now().UTC(),
	})
	meta.ModifiedAt = time.Now().UTC()
	if err := s.saveFileMetadata(ctx.storageUser, ctx.baseDEK, meta); err != nil {
		return api.Response{Success: false, Message: "Error al guardar comentario"}
	}
	return api.Response{Success: true, Message: "Comentario añadido", FileMetadata: &meta}
}

func (s *server) deleteFileComment(req api.Request) api.Response {
	commentID := strings.TrimSpace(req.CommentID)
	if commentID == "" {
		return api.Response{Success: false, Message: "Falta el identificador del comentario"}
	}

	meta, ctx, errRes := s.loadCommentableFileMetadata(req)
	if errRes.failed() {
		return errRes.response
	}

	found := -1
	for i, comment := range meta.Comments {
		if comment.ID == commentID {
			found = i
			break
		}
	}
	if found == -1 {
		return api.Response{Success: false, Message: "Comentario no encontrado"}
	}
	comment := meta.Comments[found]
	if req.Username != comment.Author && req.Username != meta.Owner {
		return api.Response{Success: false, Message: "No autorizado"}
	}

	meta.Comments = append(meta.Comments[:found], meta.Comments[found+1:]...)
	meta.ModifiedAt = time.Now().UTC()
	if err := s.saveFileMetadata(ctx.storageUser, ctx.baseDEK, meta); err != nil {
		return api.Response{Success: false, Message: "Error al borrar comentario"}
	}
	return api.Response{Success: true, Message: "Comentario borrado", FileMetadata: &meta}
}
