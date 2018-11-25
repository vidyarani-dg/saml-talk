import os

from flask import (
    Flask, 
    request, 
    render_template, 
    redirect, 
    session,
    make_response,
)

from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils


app = Flask(__name__)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml')
app.config['CLIENT_ADMIN'] = 'vidyarani.d.g@gmail.com'
app.config['FLASKY_ADMIN'] = 'vidyarani.d.g@gmail.com'


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        # https - Defaults to "off". Set this to "on" if you receive responses over HTTPS.
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/metadata/')
def metadata():
    """
    SAML metadata
    """
    req = prepare_flask_request(request)
    # Initiate SAML settings
    # Initiaize the toolkit with settings.json and the advaced_settings.json if any 
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    
    return resp


@auth.route('/saml/sso', methods=['POST'])
def saml_sso_idp_initiated_login():
    """
    SAML ACS - Attribute Consumer Service
    Single sign on validation for IDP initiated SAML logins.

    This code handles the SAML response that the IdP forwards to
    the SP through the user's client.
    """
    LOG.info("SAML SSO IDP initiated login")
    req = prepare_flask_request(request)
    # Building a OneLogin_Saml2_Auth object requires a 'request' parameter.
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    # Process the SAML Assertion
    auth.process_response()
    # Verify there are no errors
    errors = auth.get_errors()
    if errors:
        msg = "Error when processing SAML Response: %s" % (', '.join(errors))
        LOG.error(msg)

    # Retrieve the SAML Attributes if authenticated
    if auth.is_authenticated():
        session['samlUserdata'] = auth.get_attributes()
        LOG.info("SAML Attributes {}".format(session['samlUserdata']))
        try:
            # Every attribute is a list of values.
            customer_code = session['samlUserdata']['customer_code'][0].strip()
            employee_id = session['samlUserdata']['employee_id'][0].strip()
        except (TypeError, IndexError):
            LOG.error("customer_code and employee_id not present in SAML Assertion")
            return render_template("invalid_sso.html")

        if not customer_code or not employee_id:
            LOG.error("customer_code and employee_id not present in SAML Assertion")
            return render_template("invalid_sso.html")
        # Find the user
        user = User.query.filter(
            User.client_customer_code==customer_code
            ).filter(
                User.employee_id==employee_id
            ).first()

        idp_contact_email = session['samlUserdata'].get('idp_contact_email', [])
        name = session['samlUserdata'].get('name', [])

        # If the user is active, then log the user in.
        if user and user.active:
            login_user(user, False)
            message = f'Company Contact Email: {idp_contact_email}, Name: {name}'
            LOG.info(message)
            try:
                user.idp_contact_email = idp_contact_email[0]
                user.name = name[0]
                db.session.add(user)
                db.session.commit()

            except Exception:
                message = "Exception while trying to update SAML attributes " + message
                LOG.exception(message, exc_info=True)

            return redirect(request.args.get('next') or url_for('main.index'))

        else:
            subject = f"Unknown user with customer code {customer_code} and employee_id {employee_id}"
            summary_text = 'This user is not provisioned.'
            link_text = 'Please provision the user using the invite screen. '
            real_employee_id = None

        if subject and summary_text and link_text:
            to_email = [idp_contact_email] if idp_contact_email or [] 
            to_email = to_email or [app.config['CLIENT_ADMIN']]

            send_email(to=to_email,
                       subject=subject,
                       template='invalid_user',
                       cc=[app.config['FLASKY_ADMIN']],
                       customer_code=customer_code,
                       employee_id=employee_id,
                       summary_text=summary_text,
                       link_text=link_text,
                       real_employee_id=real_employee_id)
            subject += f'. The {client} Administrators have been informed.'
            LOG.error(subject)
            return render_template("invalid_sso.html")

    msg = f"Not authenticated; X509 Certificate decryption errors: saml_sso_initiated_login()"
    LOG.warning(msg)
    send_email(to=app.config['FLASKY_ADMIN'],
                subject=msg,
                template='auth/email/unauthenticated_user',
                include_msg_body=False)
    return render_template("auth/invalid_sso.html")

@app.route('/logout')
def home():
    """
    SLS - Single logout service
    """
    try:
        return_url = session['samlUserdata']['return_to'][0]
    except KeyError:
        return_url = None
    
    if return_url:
        return redirect(return_url)
        
    logout_user()
    session.clear()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
