import logging
import os
import re
import time
import urllib

from flask import current_app as app, render_template, request, redirect, url_for, session, Blueprint
from itsdangerous import TimedSerializer, BadTimeSignature, Signer, BadSignature
from passlib.hash import bcrypt_sha256

from CTFd.models import db, Teams
from CTFd import utils

auth = Blueprint('auth', __name__)


@auth.route('/confirm', methods=['POST', 'GET'])
@auth.route('/confirm/<data>', methods=['GET'])
def confirm_user(data=None):
    if not utils.get_config('verify_emails'):
        # If the CTF doesn't care about confirming email addresses then redierct to challenges
        return redirect(url_for('challenges.challenges_view'))

    # User is confirming email account
    if data and request.method == "GET":
        try:
            s = Signer(app.config['SECRET_KEY'])
            email = s.unsign(urllib.unquote_plus(data.decode('base64')))
        except BadSignature:
            return render_template('confirm.html', errors=['你的确认链接似乎有点儿问题'])
        except:
            return render_template('confirm.html', errors=['你的链接失效啦, 请重试'])
        team = Teams.query.filter_by(email=email).first_or_404()
        team.verified = True
        db.session.commit()
        logger = logging.getLogger('regs')
        logger.warn("[{0}] {1} confirmed {2}".format(time.strftime("%m/%d/%Y %X"), team.name.encode('utf-8'), team.email.encode('utf-8')))
        db.session.close()
        if utils.authed():
            return redirect(url_for('challenges.challenges_view'))
        return redirect(url_for('auth.login'))

    # User is trying to start or restart the confirmation flow
    if not utils.authed():
        return redirect(url_for('auth.login'))

    team = Teams.query.filter_by(id=session['id']).first_or_404()

    if data is None:
        if request.method == "POST":
            # User wants to resend their confirmation email
            if team.verified:
                return redirect(url_for('views.profile'))
            else:
                utils.verify_email(team.email)
            return render_template('confirm.html', team=team, infos=['你的确认链接已发送!'])
        elif request.method == "GET":
            # User has been directed to the confirm page
            team = Teams.query.filter_by(id=session['id']).first_or_404()
            if team.verified:
                # If user is already verified, redirect to their profile
                return redirect(url_for('views.profile'))
            return render_template('confirm.html', team=team)


@auth.route('/reset_password', methods=['POST', 'GET'])
@auth.route('/reset_password/<data>', methods=['POST', 'GET'])
def reset_password(data=None):
    if data is not None and request.method == "GET":
        return render_template('reset_password.html', mode='set')
    if data is not None and request.method == "POST":
        try:
            s = TimedSerializer(app.config['SECRET_KEY'])
            name = s.loads(urllib.unquote_plus(data.decode('base64')), max_age=1800)
        except BadTimeSignature:
            return render_template('reset_password.html', errors=['你的链接已过期!'])
        except:
            return render_template('reset_password.html', errors=['你的链接有点问题, 请重试'])
        team = Teams.query.filter_by(name=name).first_or_404()
        team.password = bcrypt_sha256.encrypt(request.form['password'].strip())
        db.session.commit()
        db.session.close()
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        team = Teams.query.filter_by(email=email).first()
        if not team:
            return render_template('reset_password.html', errors=['如果该账户没问题的话你将会收到一份确认邮件, 看看邮箱吧!'])
        s = TimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps(team.name)
        text = """
是否已收到邮件?

{0}/{1}

""".format(url_for('auth.reset_password', _external=True), urllib.quote_plus(token.encode('base64')))

        utils.sendmail(email, text)

        return render_template('reset_password.html', errors=['如果该账户没问题的话你将会收到一份确认邮件, 看看邮箱吧!'])
    return render_template('reset_password.html')


@auth.route('/register', methods=['POST', 'GET'])
def register():
    if not utils.can_register():
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        errors = []
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        name_len = len(name) == 0
        names = Teams.query.add_columns('name', 'id').filter_by(name=name).first()
        emails = Teams.query.add_columns('email', 'id').filter_by(email=email).first()
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.form['email'])

        if not valid_email:
            errors.append("不是有效的Email地址")
        if names:
            errors.append('该队伍名已被使用')
        if emails:
            errors.append('该邮箱已被使用')
        if pass_short:
            errors.append('密码弄长点儿')
        if pass_long:
            errors.append('密码弄短点儿')
        if name_len:
            errors.append('队伍名太长啦')

        if len(errors) > 0:
            return render_template('register.html', errors=errors, name=request.form['name'], email=request.form['email'], password=request.form['password'])
        else:
            with app.app_context():
                team = Teams(name, email.lower(), password)
                db.session.add(team)
                db.session.commit()
                db.session.flush()

                session['username'] = team.name
                session['id'] = team.id
                session['admin'] = team.admin
                session['nonce'] = utils.sha512(os.urandom(10))

                if utils.can_send_mail() and utils.get_config('verify_emails'):  # Confirming users is enabled and we can send email.
                    db.session.close()
                    logger = logging.getLogger('regs')
                    logger.warn("[{0}] {1} 已注册,但未确认 {2}".format(time.strftime("%m/%d/%Y %X"),
                                                                                     request.form['name'].encode('utf-8'),
                                                                                     request.form['email'].encode('utf-8')))

                    utils.verify_email(team.email)

                    return redirect(url_for('auth.confirm_user'))
                else:  # Don't care about confirming users
                    if utils.can_send_mail():  # We want to notify the user that they have registered.
                        utils.sendmail(request.form['email'], "{}, 你已被成功注册".format(utils.get_config('ctf_name')))

        db.session.close()

        logger = logging.getLogger('regs')
        logger.warn("[{0}] {1} 已注册 {2}".format(time.strftime("%m/%d/%Y %X"), request.form['name'].encode('utf-8'), request.form['email'].encode('utf-8')))
        return redirect(url_for('challenges.challenges_view'))
    else:
        return render_template('register.html')


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        errors = []
        name = request.form['name']
        team = Teams.query.filter_by(name=name).first()
        if team:
            if team and bcrypt_sha256.verify(request.form['password'], team.password):
                try:
                    session.regenerate()  # NO SESSION FIXATION FOR YOU
                except:
                    pass  # TODO: Some session objects don't implement regenerate :(
                session['username'] = team.name
                session['id'] = team.id
                session['admin'] = team.admin
                session['nonce'] = utils.sha512(os.urandom(10))
                db.session.close()

                logger = logging.getLogger('logins')
                logger.warn("[{0}] {1} 登陆".format(time.strftime("%m/%d/%Y %X"), session['username'].encode('utf-8')))

                if request.args.get('next') and utils.is_safe_url(request.args.get('next')):
                    return redirect(request.args.get('next'))
                return redirect(url_for('challenges.challenges_view'))
            else:  # This user exists but the password is wrong
                errors.append("用户名或密码错误")
                db.session.close()
                return render_template('login.html', errors=errors)
        else:  # This user just doesn't exist
            errors.append("用户名或密码错误")
            db.session.close()
            return render_template('login.html', errors=errors)
    else:
        db.session.close()
        return render_template('login.html')


@auth.route('/logout')
def logout():
    if utils.authed():
        session.clear()
    return redirect(url_for('views.static_html'))
