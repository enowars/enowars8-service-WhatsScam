function deleteNote(noteId) {
  fetch("/delete-note", {
    method: "POST",
    body: JSON.stringify({ noteId: noteId }),
  }).then((_res) => {
    window.location.href = "/";
  });
}
function deleteNoteGroup(noteGroupId) {
  fetch("/delete-note-group", {
    method: "POST",
    body: JSON.stringify({ noteGroupId: noteGroupId }),
  }).then((_res) => {
    window.location.href = window.location.pathname;
  });
}
