import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database

db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query transactions table and sum number of shares for each stock
    holdings = db.execute("SELECT symbol, SUM(shares)       \
                           FROM transactions                \
                           WHERE user_id=?                  \
                           GROUP BY symbol",
                           session["user_id"])

    stockTotal = 0

    for holding in holdings:

        info = lookup(holding["symbol"])

        # Add info for each holding
        holding["name"] = info["name"]
        holding["price"] = usd(info["price"])
        holding["total"] = usd(holding["SUM(shares)"] * info["price"])

        # Add to running sum for grand total for investments
        stockTotal += holding["SUM(shares)"] * info["price"]

    # Query for user's current cash balance
    user_row = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])

    return render_template("index.html", holdings=holdings, cash=usd(user_row[0]["cash"]), grandTotal=usd(stockTotal + user_row[0]["cash"]))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        stock = request.form.get("stock")
        shares = request.form.get("shares")

        # Check if all entered purchase info is valid
        if not stock:
            return apology("must enter stock symbol", 403)
        if not shares:
            return apology("must enter number of shares", 403)
        if int(shares) < 1:
            return apology("invalid number of shares", 403)

        # Look up stock info, passing error if not valid symbol
        info = lookup(stock)
        if not info:
            return apology("invalid stock symbol", 403)


        # Calculate cost of purchase and update balance if user has enough cash
        cost = info["price"] * int(shares)
        row = db.execute("SELECT cash FROM users WHERE id= :user_id",
                              user_id=session["user_id"])
        balance = row[0]["cash"]

        # Check that user has enough account balance to make purchase
        if cost > balance:
            return apology("not enough money in account to purchase", 403)

        # Record transaction in database and create table if it doesn't exist
        db.execute("CREATE TABLE IF NOT EXISTS transactions (   \
                        user_id TEXT NOT NULL,                  \
                        symbol TEXT NOT NULL,                   \
                        shares NUMERIC NOT NULL,                \
                        price NUMERIC NOT NULL,                 \
                        time TEXT DEFAULT CURRENT_TIMESTAMP)"
                        )
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price)\
                    VALUES (:user_id, :symbol, :shares, :price)",
                    user_id = session["user_id"],
                    symbol = stock.upper(),
                    shares = shares,
                    price = info["price"])

        balance = balance - cost
        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
                    balance=balance, user_id=session["user_id"])

        flash('Your purchase was successful!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
        # Query transactions table and sum number of shares for each stock
    holdings = db.execute("SELECT symbol, shares, price, time   \
                           FROM transactions                    \
                           WHERE user_id=?",
                           session["user_id"])

    # Update price to correct USD formatting
    for holding in holdings:
        holding["price"] = usd(holding["price"])

    return render_template("history.html", holdings=holdings)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Look up stock symbol and redirect to quoted page to display price
        stock = request.form.get("stock")

        info = lookup(stock)
        if not info:
            return apology("stock symbol not found", 403)

        return render_template("quoted.html", name=info["name"], symbol=info["symbol"], price=usd(info["price"]))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if all registration fields were completed
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not confirmation:
            return apology("must confirm password", 403)

        # Check user database to see if username exists
        check = db.execute("SELECT username FROM users WHERE username = :username",
                            username=username)
        if check:
            return apology("username already taken", 403)

        # Check password and confirmation match
        if password != confirmation:
            return apology("passwords do not match", 403)

        # Insert user information into database then return to home page
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :pw)",
                    username=username, pw = generate_password_hash(password))

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        stock = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check if all entered purchase info is valid
        if not stock:
            return apology("must select stock symbol", 403)
        if not shares:
            return apology("must enter number of shares", 403)
        if int(shares) < 1:
            return apology("invalid number of shares", 403)

        # Look up stock info, passing error if not valid symbol
        info = lookup(stock)
        if not info:
            return apology("invalid stock symbol", 403)

        # Check that user has enough shares to sell
        holding = db.execute("SELECT SUM(shares)    \
                              FROM transactions     \
                              WHERE symbol=? AND user_id=?",
                              stock, session["user_id"])
        print(holding)
        if holding[0]["SUM(shares)"] < int(shares):
            return apology("not enough shares", 403)

        # Calculate price of sale and update balance
        earnings = info["price"] * int(shares)
        row = db.execute("SELECT cash FROM users WHERE id= :user_id",
                              user_id=session["user_id"])
        balance = row[0]["cash"]

        # Record transaction in database
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price)\
                    VALUES (:user_id, :symbol, :shares, :price)",
                    user_id = session["user_id"],
                    symbol = stock.upper(),
                    shares = int(shares) * -1,
                    price = info["price"])

        balance = balance + earnings
        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
                    balance=balance, user_id=session["user_id"])

        flash('Your transaction was successful!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        holdings = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id=?", session["user_id"])
        return render_template("sell.html", holdings=holdings)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        deposit = request.form.get("deposit")
        deposit = deposit.replace('$','').replace(',','')
        db.execute("UPDATE users SET cash=cash + :deposit WHERE id=:user", deposit=deposit, user=session["user_id"])

        flash('Your deposit was successful!')
        return render_template("deposit.html")

    else:
        return render_template("deposit.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
