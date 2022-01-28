import json, re, stripe, json, os, mysql.connector, random, string, datetime, werkzeug
from rich import print
from flask_simplelogin import login_required
from flask import Flask, jsonify, redirect, request, abort, render_template, send_from_directory, make_response, flash, url_for
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from functools import wraps
from supabase import create_client, Client
import pyotp
import base64
#https://stackabuse.com/serving-static-files-with-flask/

app = Flask(__name__)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = '*@maildomain.com'
app.config['MAIL_PASSWORD'] = '*'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['SIMPLELOGIN_USERNAME'] = 'admin'
app.config['SIMPLELOGIN_PASSWORD'] = 'Ramzi007'
app.config["SECRET_KEY"] = '*'
mail = Mail(app)

endpoint_secret = "*"
stripe.api_key="*"

url = "https://*.supabase.co"
supa_secret_key = "*"
supabase: Client = create_client(url, supa_secret_key)

YOUR_DOMAIN = 'https://*.ngrok.io' #
key = open(".//auth.key", "rb").read()
a = Fernet(key)

def sort(d, c, r:bool):
    users = sorted(d, key=lambda k: k[c], reverse=bool(r))
    return users

def supaget(table:str, select, dict:dict):
    data = supabase.table(table).select(str(select))
    for k,v in dict.items():
        data = data.eq(f"{k}=",f"{v}")
    data = data.execute()
    data = data.get("data", [])
    return(data)

def supaupdate(table:str, update:str, where:dict):
    data = supabase.table(table).update(update)
    for k,v in where.items():
        data = data.eq(f"{k}=",f"{v}")
    data = data.execute()
    data = data.get("data", [])
    return data

def supainsert(table:str, insert:str, where:dict):
    data = supabase.table(table).insert(insert)
    for k,v in where.items():
        data = data.eq(f"{k}=",f"{v}")
    data = data.execute()
    data = data.get("data", [])
    #assert len(data.get("data", [])) > 0
    return data

def get_pass(auth):
    bpass = a.decrypt(bytes(auth, 'utf-8'))
    return bpass.decode("utf8")

def auth_required(f):
    @wraps(f)
    def user_func(*args, **kwargs):
        if request.cookies.get('uuid') and request.cookies.get('auth') != None:
            u = supaget('cards', "*", {'card_uid':f"{request.cookies.get('uuid')}","password":get_pass(request.cookies.get('auth'))})
            try:
                u = u[0]
            except KeyError as e:
                r = make_response(redirect("/login/", code=303))
                r.delete_cookie(key='uuid', path='/')
                r.delete_cookie(key='auth', path='/')
                return r
            if u["admin"] == '1' or u["admin"] == '0':
                return f(*args, **kwargs)
        else:
            return redirect("/login/", code=303)
    return user_func

def admin_required(f):
    @wraps(f)
    def admin_func(*args, **kwargs):
        if request.cookies.get('uuid') and request.cookies.get('auth') != None:
            u = supaget('cards', "*", {'card_uid':f"{request.cookies.get('uuid')}","password":get_pass(request.cookies.get('auth'))})
            try:
                u = u[0]
            except KeyError as e:
                r = make_response(redirect("/login/", code=303))
                r.delete_cookie(key='uuid', path='/')
                r.delete_cookie(key='auth', path='/')
                return r
            if u["admin"] == '1':
                return f(*args, **kwargs)
            else:
                return redirect('/tickets/', code=303)
        else:
            return redirect("/login/", code=303)
    return admin_func

def get_user_info():
    try:
        card = request.cookies.get('uuid')
        return supaget('cards', "*", {'card_uid':f"{card}"})[0]
    except Exception as e:
        print(e)
        return False

def get_admin_info():
    try:
        card = request.cookies.get('uuid')
        return supaget('cards', "*", {'card_uid':f"{card}"})[0]
    except Exception as e:
        print(e)
        return False


def txn_id():
    return "{0}-{1}-{2}".format(''.join(random.choice(string.ascii_uppercase) for x in range(4)),''.join(random.choice(string.digits) for x in range(4)),''.join(random.choice(string.ascii_uppercase) for x in range(4)))

def reference_id():
    return "{0}-{1}-{2}".format(''.join(random.choice(string.digits) for x in range(4)),''.join(random.choice(string.ascii_uppercase) for x in range(4)),''.join(random.choice(string.digits) for x in range(4)))


@app.errorhandler(404)
def fourohfour(exception):
    return render_template("error.html", error = 404), 404

@app.errorhandler(403)
def fourohthree(exception):
    return render_template("error.html", error = 403)

@app.route('/', defaults={'path': '/tickets'})
@app.route("/<path:path>")
def static_dir(path):
    return send_from_directory("templates", path)


#app.route('/admin/<path:path>', defaults={'path': ''})
#app.route("/admin/<path:path>")
#def adminpath(path):
#   return send_from_directory("admin", path)

@app.route('/')
def homeroot():
    return redirect("/tickets/", code=303)

@app.route('/tickets/')
def home():
    return render_template("index.html", data=get_user_info())

@app.route('/tickets/2fa', methods=["GET","POST"])
@auth_required
def mfa():
    x = get_user_info()['card_uid']
    if request.method == "POST":
        secret = request.form.get("secret")
        otp = int(request.form.get("otp"))
        print(f'---{secret}---{otp}')
        if pyotp.TOTP(secret).verify(otp):
            if request.form.get("2fa") == 'enable':
                supaupdate('cards', {"has_2fa":'1'}, {'card_uid':x})
            elif request.form.get("2fa") == 'disable':
                supaupdate('cards', {"has_2fa":'0'}, {'card_uid':x})
            flash(f"The 2FA token is valid, 2FA has been {request.form.get('2fa')}d!", "success")
            return redirect(url_for("test"))
        else:
            flash("The TOTP 2FA token is invalid, try again!", "danger")
            return redirect(url_for("test"))
    else:
        b = bytes(x, 'utf-8')
        c = base64.b32encode(base64.b32encode(base64.b32encode(base64.b32encode(b))))
        qr = pyotp.TOTP(c).provisioning_uri(name=x, issuer_name="")
        secret = pyotp.TOTP(c)
        #return f'{x}<br>{b}<br>{secret}<br>{unsecret} <br> {secret.now()}'
        return render_template("2fa.html", data=get_user_info(), qr = qr, secret = c.decode('utf-8'))

@app.route('/login/', methods=["GET","POST"])
def login():
    pass_2fa = 0
    if request.method == "POST":
        card = request.form["username"]
        password = request.form["password"]
        if request.form.get('login') == 'mfa':
            otp = request.form["mfa"]
            b = bytes(card, 'utf-8')
            secret = base64.b32encode(base64.b32encode(base64.b32encode(base64.b32encode(b))))
            print(secret, otp)
            if pyotp.TOTP(secret).verify(otp):
                pass_2fa = 1
            else:
                flash("The 6-digit 2FA code you entered you entered was incorrect, try again!", "danger")
                return render_template("login.html", logintype = "user", ph="User ID", data=get_user_info(), mfa=1)
        user = supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})
        try:
            user = user[0]
        except (KeyError, IndexError):
            user = None
        if user == None:
            return render_template("login.html", logintype= "user", ph = "User ID", error = "ERROR: Incorrect Username or Password", data=get_user_info())
        else:
            if user["has_2fa"] == 1 and pass_2fa == 0:
                flash("Please enter your 6-digit 2FA code from your authenticator application", "danger")
                return render_template("login.html", logintype = "user", ph="User ID", data=get_user_info(), mfa=1)
            if user["has_2fa"] == 0 or pass_2fa == 1:
                password = password.encode()
                penc = a.encrypt(password)
                td = datetime.datetime.now()
                inweek = td + datetime.timedelta(days=14)
                resp = make_response(f"""Logged in as: {user["fullname"]} - ({user["card_uid"]}) <script>var timer = setTimeout(function() {{window.location='/tickets'}}, 3000);</script>""")
                resp.set_cookie('uuid', card, path="/", expires=inweek)
                resp.set_cookie('auth', penc, path="/", expires=inweek)
                return resp
    elif request.method == "GET":
        if request.cookies.get('uuid') and request.cookies.get('auth') != None:
            return redirect('/tickets', code=303)
        else:
            return render_template("login.html", logintype = "user", ph="User ID", data=get_user_info(), mfa = 0)


@app.route('/logout/', methods=["GET","POST"])
def logout():
    if request.cookies.get('uuid') and request.cookies.get('auth') != None:
        resp = make_response(f"OK - Logged out of {get_user_info()}<script>var timer = setTimeout(function() {{window.location='/tickets/'}}, 3000);</script>")
        resp.delete_cookie(key='uuid', path='/')
        resp.delete_cookie(key='auth', path='/')
    else:
        return "You are not logged in, redirecting you to the login page... <script>var timer = setTimeout(function() {{window.location='/login'}}, 3000);</script>"
    return resp

@app.route('/tickets/<path:path>')
def returncss(path):
    return send_from_directory("templates",path)

@app.route('/admin/', methods=["GET", "POST"])
@admin_required #https://flask-simple-login.readthedocs.io/en/latest/usage.html#checking-if-user-is-logged-in
def admin():
    if request.method == "POST":
        card = request.cookies.get('uuid')
        password = get_pass(request.cookies.get('auth'))
        try:
            action = request.form["action"]
        except:
            pass
        if action == "add_user":
            card = request.form["card-id"]
            password = request.form["password"]
            fname = request.form["fname"]
            data = supaget('cards', "*", {'card_uid':f"{card}"})
            print(data)
            try:
                data = data[0]
            except (KeyError, IndexError):
                print("Key Error")
                data = None
            if data == None:
                d = supainsert('cards', {"card_uid":f"{card}", "password":f"{password}","fullname":fname}, {})
                return f"Success, added Card ID {card} to system.<script>var timer = setTimeout(function() {{window.location='/admin/'}}, 3000);</script>"
            elif data['card_uid'] == card:
                return f"{data[0]['fullname']}'s account already exists!<script>var timer = setTimeout(function() {{window.location='/admin/'}}, 3000);</script>"
            else:
                return "Request Aborted", 500

    else:
        return render_template("admin.html", data=get_admin_info())

@app.route('/admin/action', methods=["GET", "POST"])
def adminaction():
    if request.method == "POST":
        try:
            a = request.form["action"]
        except:
            pass
        if a == "add_user":
            action = "add_user"
        elif a == "freeze_user":
            action = "freeze"
        return render_template("action.html", action=action, data=get_admin_info())
    else:
        return render_template("action.html", data=get_admin_info())

@app.route('/admin/<path:path>')
def admindir(path):
    return send_from_directory("admin", path)

@app.route('/admin/table', methods=["GET","POST"])
@admin_required
def table():
    try:
        form = request.form["action"]
    except:
        return "Please supply an action to this table :( </p><script>var timer = setTimeout(function() {{window.location='/admin/'}}, 3000);</script></body></html>"
    if request.form["action"] == "list_users":
        title = "List Users | ISU Ticket System"
        list_u = supaget('cards', "card_uid, fullname, lunchtickets, frozen", {})
        users = sort(list_u, 'fullname', False)
        return render_template("table.html", users=users, headers=["Full Name", "Card ID", "Number of Tickets", "State"], title=title, action="list_users", data=get_user_info())
    elif request.form["action"] == "transaction":
        title = "List Transactions | ISU Ticket System"
        users = supaget('transaction_history', "user_id, tx_id, tx_val, description, date_time", {})
        users = sort(users, 'date_time', True)
        return render_template("table.html", users=users, headers=["Timestamp", "User ID", "Transaction ID", "Transaction Amount", "Description"], title=title, action="transaction", data=get_user_info())

@app.route('/tickets/manage', methods=["GET","POST"])
@auth_required
def manage():
    if request.method == "GET":
        return render_template('manage.html', data=get_user_info())
    else:
        card = request.cookies.get('uuid')
        password = get_pass(request.cookies.get('auth'))
        try:
            action = request.form["action"]
        except:
            pass
        if action == 'send_user':
            action = 'send'
            return render_template("lock.html", action=action, data=get_user_info())
        if action == 'lock':
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            data = supaget('cards', "*", {'card_uid':card, 'password':password})[0]
            if data['frozen'] == '1':
                return "Account already locked<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"
            else:
                #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHANGE IT)
                supaupdate('cards', {"frozen":'1'}, {'card_uid':card})
                return """Account locked successfully, go back to the <a href="/tickets/manage">Card Management Page</a> to unlock it. <script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"""
        if action == 'unlock':
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            data = supaget('cards', "*", {'card_uid':card, 'password':password})[0]
            if data['frozen'] == '0':
                return "Account already unlocked. <script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"
            else:
                supaupdate('cards', {"frozen":'0'}, {'card_uid':card})
                return """Account unlocked successfully<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"""
        if action == 'send':
            qty = request.form["number_tx_to_send"]
            recipient = request.form["to"]
            transaction_id = txn_id()
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            data = supaget('cards', "*", {'card_uid':f"{card}",'password':password})
            try:
                data = data[0]
            except (KeyError, IndexError):
                data = None
            if data == None:
                return "Incorrect Username or Password<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"
            if card == recipient:
                return "You can't send yourself tickets!<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"
            elif data['frozen'] == '1':
                return f"""Account {card} is locked, please <a href="/tickets/manage">unlock</a> it first to send tickets!<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script>"""
            else:
                current = data['lunchtickets']
                new = current - int(qty)
                data2 = supaget('cards', "*", {'card_uid':recipient})
                try:
                    data2 = data2[0]
                except (KeyError, IndexError) as e:
                    print(e)
                    data2 = None
                if data2 == None:
                    return f"<html><body><p>The ID you supplied does not exist in our system. Please try again.</p><script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 3000);</script></body></html>"
                newrec = data2['lunchtickets'] + int(qty)
                if new < 0:
                    return f"You only have {current} tickets, you cannot send {qty} tickets to {recipient}<br><br>You will be automatically redirected...<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 4000);</script>"
                else:
                    try:
                        #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
                        dat = datetime.datetime.now()
                        dat = str(dat).split('.')[0]
                        supainsert('transaction_history', {'user_id' : card, 'tx_id' : transaction_id, "tx_val" : f"-{qty}","description":f"To: {data2['fullname']}", "date_time":f"{dat}"},{})
                        supainsert('transaction_history', {'user_id' : recipient, 'tx_id' : transaction_id, "tx_val" : f"+{qty}","description":f"From: {data['fullname']}", "date_time":f"{dat}"},{})
                    except Exception as e:
                        print(e)
                        return f"Please create a new transaction, something went wrong. This will probably happen if you reload the page after sending the tickets. Don't worry though, they've been sent"
                    #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
                    #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
                    supaupdate('cards', {"lunchtickets":new}, {'card_uid': card})
                    supaupdate('cards', {"lunchtickets":newrec}, {'card_uid': recipient})
                    return f"You have {current} tickets and just sent {qty} tickets to {recipient}, making your new balance {new}, and the recipient's ({recipient}) balance {newrec}<br><br>You will be automatically redirected...<script>var timer = setTimeout(function() {{window.location='/tickets/manage'}}, 5000);</script>"
        if action == "history":
            title = "List Transactions | ISU Ticket System"
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            users = supaget('transaction_history', "user_id, tx_id, tx_val, description, date_time", {'user_id':card})
            users = sort(users, 'date_time', True)
            current = supaget('cards', "lunchtickets", {'card_uid':card})
            current = current[0]["lunchtickets"]
            return render_template("table.html", users=users, headers=["Timestamp", "Transaction ID", "Transaction Amount", "Description"], title=title, action="history", current=current, data=get_user_info())
        if action == "check_balance":
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            data = supaget('cards',"*", {"card_uid":card})
            try:
                data = data[0]
            except (KeyError, IndexError):
                print("Key Error")
                data = None
            if data == None:
                return f"<html><body><p>The ID you supplied does not exist in our system. Please try again.</p><script>var timer = setTimeout(function() {{window.location='/tickets/query'}}, 3000);</script></body></html>"
            else:
                fname = data["fullname"]
                tx = data["lunchtickets"]
                id = data["card_uid"]
                resp =  make_response(render_template("query_result.html", fname=fname, value=tx, id=id, data=get_user_info()))
                #cookies = request.cookies.get('card-id')
                #if cookies == None:
                #    ncookie = card
                #    resp.set_cookie("card-id", ncookie, path='/')
                #else:
                #    cookies = list(cookies.split(" "))
                #    print(cookies)
                #    ncookie = ""
                #    for count, i in enumerate(cookies, start=0):
                #        if len(i) < 6:
                #            pass
                #        if count == 0:
                #            ncookie += f"{i}"
                #        else:
                #            ncookie += f" {i}"
                #    if card not in ncookie:
                #        ncookie += f" {card}"
                #    print(ncookie)
                #    resp.set_cookie("card-id", ncookie, path='/')
                return resp
        if action == "changepassword":
            return render_template("lock.html", action=action, data=get_user_info())
        if action == "change_password":
            current = request.form["password"]
            newp = request.form["newpassword"]
            if current == newp:
                return render_template("lock.html", action="changepassword", error = "ERROR: New password can't be the same as the old one!", data=get_user_info(), logintype="user")
            data = supaget('cards','*', {'card_uid':"{0}".format(card), 'password':"{0}".format(current)})
            try:
                print(data)
                data = data[0]
            except (KeyError, IndexError):
                print("Key Error")
                data = None
            if data == None:
                return render_template("lock.html", action="changepassword", error = "ERROR: Incorrect Username or Password", data=get_user_info())
            else:
                print(supaupdate('cards', {'password' : '{0}'.format(newp)}, {'card_uid':'{0}'.format(card)}))
                resp = make_response(render_template("login.html", ph="User ID",success="Successfully updated your password", data=get_user_info(), logintype="user"))
                resp.delete_cookie(key='uuid', path='/')
                resp.delete_cookie(key='auth', path='/')
                return resp


@app.route('/tickets/purchase', defaults={'path': ''})
@app.route("/tickets/purchase/<path:path>")
def checkout(path):
    return render_template('checkout.html', data=get_user_info())

@app.route('/tickets/success')
def success():
    return send_from_directory("templates", 'success.html', data=get_user_info())

@app.route("/tickets/cancelled")
def cancelled():
    return send_from_directory("templates", 'cancelled.html', data=get_user_info())

@app.route("/tickets/query", methods=["POST", "GET"])
@auth_required
def query():
    if request.method == "GET":
        cookie = request.cookies.get('card-id')
        if cookie == None:
            cookie = ""
        return render_template("query.html", value="", data=get_user_info())


@app.route('/tickets/momoney', methods=['POST','GET'])
def momoney():
    if request.method == "POST":
        try:
            card = request.form["card-id"]
            for k, v in request.form.items():
                print(f"{k}: {v}")
        except:
            pass
    return "200"

@app.route('/tickets/stripe', methods=['POST','GET'])
def webhook():
    if request.method == 'POST':
        event = None
        payload = request.data
        sig_header = request.headers['STRIPE_SIGNATURE']

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError as e:
            return "POST REQUEST VALUERROR"
        except stripe.error.SignatureVerificationError as e:
            return "Incorrect signing secret"
        print(event['type'])
        print(event['type'])
        print(event['data']['object'])
        if event['type'] == 'charge.captured':
            charge = event['data']['object']
        #elif event['type'] == 'charge.dispute.created':
        #    amount = event['data']['object']['amount']
        #    amount = amount/12000
        elif event['type'] == 'charge.succeeded':
            obj = event['data']['object']
            charge = obj['amount']
            curr = obj['currency']
            print(charge)
            print(curr)
        elif event['type'] == 'checkout.session.completed':

            tx_id = reference_id()
            obj = event['data']['object']
            print(obj)
            email = obj['customer_details']['email']
            card = obj['metadata']['card-id']
            price = stripe.Price.retrieve("price_1JzoJyEje0hlE4d2jJCs75PU")
            price = int(price['unit_amount']/100)
            paid = int(obj['amount_total']/100)
            qty = int(paid/price)
            print(email, card, qty)
            #supaget('cards', "*", {"card_uid":f"{card}", "password":f"{password}"})[0] SELECT NOT INSERT (CHNAGE IT)
            data = supaget('cards', '*', {"card_uid":f"{card}"})
            try:
                data = data[0]
            except (KeyError, IndexError):
                print("Key Error")
                data = None
            try:
                msg = Message(f'Ticket Purchase confirmation', sender = 'rhijjawi@isumail.ac.ug', recipients = [email])
                msg.body = f"This email confirms that you have purchased {qty} tickets for account {card}, please contact the Business Office for assistance."
                mail.send(msg)
            except Exception as e:
                print(e)
            o = int(data["lunchtickets"])
            n = o+qty
            print(n, card)
            dat = datetime.datetime.now()
            dat = str(dat).split('.')[0]
            name = supaget('cards',"fullname", {"card_uid":card})[0]["fullname"]
            supaupdate('cards', {"lunchtickets":n}, {"card_uid":card})
            supainsert('transaction_history', {'user_id' : card, 'tx_id' : tx_id, "tx_val" : f"+{qty}","description":f"{name} Topped-up via Stripe", "date_time":dat}, {})
            #charge = obj['amount']
            #curr = obj['currency']
            #print(charge)
            #print(curr)
        elif event['type'] == 'payment_intent.succeeded': #Payment authorized
            obj = event['data']['object']
            email = obj['charges']['data'][0]['billing_details']['email']
            outcome = obj['charges']['data'][0]['outcome']['type'] #should be authorized
            reciepturl = obj['charges']['data'][0]['receipt_url']
            print(email,outcome,reciepturl)
        else:
            print('Unhandled event type {}'.format(event['type']))
        return jsonify(success=True)
    else:
        return redirect("/tickets", code=303)

@app.route('/tickets/create-checkout-session', methods=['POST'])
def create_checkout_session():
    card = request.form["card-id"]
    data = supaget('cards',"*", {"card_uid":card})
    try:
        data = data[0]
    except (KeyError, IndexError):
        print("Key Error")
        data = None
    if data == None:
        return render_template('checkout.html', data=get_user_info(), error="This ID does not exist in our system")
    else:
        try:
            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        # Provide the exact Price ID (e.g. pr_1234) of the product you want to sell
                        'price': 'price_1JzoJyEje0hlE4d2jJCs75PU',
                        'adjustable_quantity': {
                        'enabled': True,
                        'minimum': 5,
                        'maximum': 50},
                        'quantity': 5,
                    },
                ],
                metadata = {'card-id': card},
                mode='payment',
                success_url= YOUR_DOMAIN + '/success.html',
                cancel_url= YOUR_DOMAIN + '/cancelled.html',
            )
        except KeyError as e:
            return str(e)
        return redirect(checkout_session.url, code=303)


if __name__ == '__main__':
    app.run(host= '0.0.0.0', port=5000, debug=True)
