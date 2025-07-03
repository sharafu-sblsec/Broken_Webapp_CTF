function showCloseAlert() {
  fetch("/close_account", {
    method: "POST"
  })
  .then(response => {
    if (response.ok) {
      Swal.fire({
        title: 'Request Sent!',
        text: 'Your account closure request has been submitted. Admin will contact you shortly.',
        icon: 'info',
        confirmButtonText: 'OK'
      });
    } else {
      Swal.fire({
        title: 'Failed!',
        text: 'There was a problem sending your request. Please try again.',
        icon: 'error',
        confirmButtonText: 'OK'
      });
    }
  })
  .catch(error => {
    Swal.fire({
      title: 'Error!',
      text: 'Could not connect to server.',
      icon: 'error',
      confirmButtonText: 'OK'
    });
  });
}
