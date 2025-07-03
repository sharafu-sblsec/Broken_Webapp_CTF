if (typeof loginerror !== 'undefined' && loginerror === true) {
  Swal.fire({
    icon: 'error',
    title: 'Login Failed',
    text: 'Incorrect username or password.',
    confirmButtonText: 'Try Again',
    allowOutsideClick: false
  }).then((result) => {
    if (result.isConfirmed) {
      window.location.href = "/login";
    }
  });
}