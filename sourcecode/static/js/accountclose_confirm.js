document.querySelector('.btn-back-red')?.addEventListener('click', function (e) {
  e.preventDefault(); // Prevent link from navigating

  Swal.fire({
    title: 'Are you sure?',
    text: "You are about to permanently delete this user account.",
    icon: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#d33',
    cancelButtonColor: '#6c757d',
    confirmButtonText: 'Yes, delete it!',
    reverseButtons: true
  }).then((result) => {
    if (result.isConfirmed) {
      window.location.href = e.target.href; // Go to /admin/delete-user/<user_id>
    }
  });
});