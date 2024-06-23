function deletemessage(messageId) {
  fetch("/delete-message", {
    method: "POST",
    body: JSON.stringify({ messageId: messageId }),
  }).then((_res) => {
    window.location.href = "/";
  });
}
function deleteMessageGroup(MessageGroupId) {
  fetch("/delete-message-group", {
    method: "POST",
    body: JSON.stringify({ MessageGroupId: MessageGroupId }),
  }).then((_res) => {
    window.location.href = window.location.pathname;
  });
}
