# Invoicing App

This project provides a lightweight invoicing and reminder
application built with [Flask](https://flask.palletsprojects.com/).
It’s aimed at small and medium businesses that need to keep track
of customers and invoices and automatically remind clients when
payment is due or overdue.  The app is intentionally simple so you
can extend it with your own features such as PDF invoice
generation, payment gateways or user authentication.

## Features

* **Customer management** – create, edit and remove customers.  A
  customer has a name and an email address.  When a customer is
  deleted all associated invoices are also removed.
* **Invoice management** – create, edit and remove invoices.  Each
  invoice belongs to a customer, has an amount, optional description,
  due date and a paid flag.
* **Automated reminders** – a background job (powered by
  [APScheduler](https://apscheduler.readthedocs.io/)) runs hourly and
  checks for invoices whose due date is today or in the past.  For
  each unpaid invoice a reminder is printed to the console.  You can
  replace the `send_invoice_reminder` function in `app.py` with code
  that sends real emails (using `smtplib` or a service such as
  SendGrid).  The Python standard library module `smtplib` can be
  used to send email via an SMTP server【824084456160461†L59-L63】.
* **Manual reminders** – from the invoice list you can send a
  one‑off reminder for an unpaid invoice.

## Installation

1. Install Python 3.9 or newer.
2. Create a virtual environment and activate it (optional but
   recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:

   ```bash
   python app.py
   ```

5. Open your browser and navigate to `http://localhost:5000` to access
   the dashboard.  The database will be created on first run.

## Customising reminders

The reminder job is defined in `check_due_invoices` inside
`app.py`.  Currently the job looks for invoices with a due date
earlier than or equal to today and which have not been marked as
paid.  You can adjust this logic to send reminders a few days in
advance by comparing `invoice.due_date` to `date.today() + timedelta(days=N)`.

To send real emails instead of printing to the console, modify
`send_invoice_reminder` to connect to your mail server using
`smtplib.SMTP` and call `smtp.sendmail(...)`【824084456160461†L59-L63】.  Make sure you handle
authentication, TLS/SSL and error handling as appropriate for your
SMTP provider.

## Database schema

The app uses SQLite via SQLAlchemy.  Two tables are created:

* `customer`: stores id, name and email for each customer.
* `invoice`: stores id, customer_id (foreign key), description,
  amount, due_date and paid flag.

You can explore or modify the schema by editing the models in
`app.py`.

## License

This project is released under the MIT License.  Feel free to use
and modify it for your own needs.