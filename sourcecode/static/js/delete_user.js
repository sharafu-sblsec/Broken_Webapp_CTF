document.getElementById('deleteUserForm')?.addEventListener('submit', function(e) {
  e.preventDefault();

  Swal.fire({
    title: 'Are you sure?',
    text: "You are about to delete this user account. This action cannot be undone.",
    icon: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#d33',
    cancelButtonColor: '#6c757d',
    confirmButtonText: 'Yes, delete it!',
    reverseButtons: true
  }).then((result) => {
    if (result.isConfirmed) {
      e.target.submit();
    }
  });
});


if (window.userDeleted === true) {
  Swal.fire({
    icon: 'success',
    title: 'Deleted!',
    text: 'The user account has been permanently removed.',
  }).then(() => {
    window.location.href = "/admin?id=1";
  });
}