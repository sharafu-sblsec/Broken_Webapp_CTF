const userId = document.getElementById('transferForm').dataset.userid;

document.getElementById('transferForm').addEventListener('submit', function(e) {
  e.preventDefault();

  const userId = document.getElementById('transferForm').dataset.userid;
  const recipient = document.getElementById('recipient_account').value.trim();
  const amount = document.getElementById('amount').value.trim();

  if (!recipient || !amount) {
    Swal.fire('Error', 'All fields are required.', 'error');
    return;
  }

  if (isNaN(amount) || parseFloat(amount) <= 0) {
    Swal.fire('Invalid Amount', 'Please enter a valid number greater than 0.', 'error');
    return;
  }

  fetch('/moneytransfer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      recipient_account: recipient,
      amount: amount
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.error) {
      switch (data.error) {
        case 'account_not_found':
          Swal.fire('Error', 'Recipient account number not found.', 'error');
          break;
        case 'insufficient_funds':
          Swal.fire('Error', 'You do not have enough balance for this transfer.', 'error');
          break;
        case 'invalid_amount':
          Swal.fire('Error', 'Please enter a valid numeric amount.', 'error');
          break;
        case 'self_transfer':
          Swal.fire('Error', 'Cannot transfer money to your own account.', 'error');
          break;
        default:
          Swal.fire('Error', data.error, 'error');
      }
    } else {
      Swal.fire('Success', `Successfully transferred $${amount} to account ${recipient}`, 'success')
        .then(() => {
          window.location.href = `/dashboard?id=${userId}`;
        });
    }
  })
  .catch(error => {
    Swal.fire('Error', 'An error occurred while processing the request.', 'error');
  });
});