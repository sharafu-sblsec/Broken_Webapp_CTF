if (typeof usernameTaken !== 'undefined' && usernameTaken === true) {
  Swal.fire({
    icon: 'error',
    title: 'Username already exists',
    text: 'Please choose a different username.',
  });
}

if (typeof registrationSuccess !== 'undefined' && registrationSuccess === true) {
  Swal.fire({
    icon: 'success',
    title: 'Account Created!',
    text: 'You can now log in to your account.',
    confirmButtonText: 'OK'
  }).then(() => {
    window.location.href = "/login";
  });
}

if (typeof weakPassword !== 'undefined' && weakPassword === true) {
  Swal.fire({
    icon: 'error',
    title: 'Weak Password',
    text: 'Password must be 6 to 50 characters.',
  });
}

if (typeof invalidUsername !== 'undefined' && invalidUsername === true) {
  Swal.fire({
    icon: 'error',
    title: 'Invalid Username',
    text: 'Username must only contain letters, numbers, and underscores.',
  });
}

if (typeof missingFields !== 'undefined' && missingFields === true) {
  Swal.fire({
    icon: 'warning',
    title: 'All Fields Required',
    text: 'Please fill out all fields before submitting.',
  });
}


