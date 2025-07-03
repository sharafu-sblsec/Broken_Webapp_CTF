if (typeof addSuccess !== 'undefined') {
  Swal.fire({ icon: 'success', title: 'Success!', text: addSuccess });
}
if (typeof addError !== 'undefined') {
  Swal.fire({ icon: 'error', title: 'Error', text: addError });
}