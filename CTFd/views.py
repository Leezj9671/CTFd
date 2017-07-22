import os
import re

from flask import current_app as app, render_template, request, redirect, abort, jsonify, url_for, session, Blueprint, Response, send_file
from flask.helpers import safe_join
from jinja2.exceptions import TemplateNotFound
from passlib.hash import bcrypt_sha256

from CTFd.models import db, Teams, Solves, Awards, Files, Pages
from CTFd.utils import cache, markdown
from CTFd import utils

views = Blueprint('views', __name__)


@views.route('/setup', methods=['GET', 'POST'])
def setup():
    # with app.app_context():
        # admin = Teams.query.filter_by(admin=True).first()

    if not utils.is_setup():
        if not session.get('nonce'):
            session['nonce'] = utils.sha512(os.urandom(10))
        if request.method == 'POST':
            ctf_name = request.form['ctf_name']
            ctf_name = utils.set_config('ctf_name', ctf_name)

            # CSS
            css = utils.set_config('start', '')

            # Admin user
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            admin = Teams(name, email, password)
            admin.admin = True
            admin.banned = True

            # Index page
            page = Pages('index', """<div class="container main-container">
    <img class="logo" src="themes/original/static/img/logo.png" />
    <h4 class="text-center">注意：为了能有良好的体验，请在PC版浏览器打开</h4>
    <h4 class="text-left">何为CTF？</h4>
    <h5 class="text-left">CTF（Capture The Flag）中文一般译作夺旗赛，在网络安全领域中指的是网络安全技术人员之间进行技术竞技的一种比赛形式。CTF起源于1996年DEFCON全球黑客大会，以代替之前黑客们通过互相发起真实攻击进行技术比拼的方式。</h5>
    <h4 class="text-left">如何比拼？</h4>
    <h5 class="text-left">会有不同类型的题目，一般会通过一些抓包／改包／破解／逆向／各种漏洞等的攻击利用方式找到系统中存在的一个字符串（被称为Flag）,提交这个字符串，如果正确系统会标示为已解决，获得相应积分。</h5>
    <h4 class="text-left" style="color:red">对开发人员的好处？</h4>
    <h5 class="text-left" style="color:red">以一种带有趣味性和很强动手实操的方式，深刻了解众多漏洞的危害，提高安全意识。</h5>
    <h4 class="text-left">注意事项</h4>
    <h5 class="text-left">1，禁止破坏系统的环境。某些漏洞被利用后可能会超出原有设计的危害，比如可以搞挂比赛环境等。要杜绝，只需要拿到ctf的字符串即可。</h5>
    <h5 class="text-left">2，禁止对环境进行DOS攻击。这里不是DOS攻击的练习场，并且会影响到他人的练习。</h5>
    <h5 class="text-left" style="color:red">3，建议先从简单的一个系列开始《基础系列》</h5>
    <h3 class="text-center"><a target="_self" href="/challenges">Let's Begin</a></h3>
</div>""".format(request.script_root))

            # max attempts per challenge
            max_tries = utils.set_config('max_tries', 0)

            # Start time
            start = utils.set_config('start', None)
            end = utils.set_config('end', None)
            freeze = utils.set_config('freeze', None)

            # Challenges cannot be viewed by unregistered users
            view_challenges_unregistered = utils.set_config('view_challenges_unregistered', None)

            # Allow/Disallow registration
            prevent_registration = utils.set_config('prevent_registration', None)

            # Verify emails
            verify_emails = utils.set_config('verify_emails', None)

            mail_server = utils.set_config('mail_server', None)
            mail_port = utils.set_config('mail_port', None)
            mail_tls = utils.set_config('mail_tls', None)
            mail_ssl = utils.set_config('mail_ssl', None)
            mail_username = utils.set_config('mail_username', None)
            mail_password = utils.set_config('mail_password', None)

            setup = utils.set_config('setup', True)

            db.session.add(page)
            db.session.add(admin)
            db.session.commit()

            session['username'] = admin.name
            session['id'] = admin.id
            session['admin'] = admin.admin
            session['nonce'] = utils.sha512(os.urandom(10))

            db.session.close()
            app.setup = False
            with app.app_context():
                cache.clear()

            return redirect(url_for('views.static_html'))
        return render_template('setup.html', nonce=session.get('nonce'))
    return redirect(url_for('views.static_html'))


# Custom CSS handler
@views.route('/static/user.css')
def custom_css():
    return Response(utils.get_config('css'), mimetype='text/css')


# Static HTML files
@views.route("/", defaults={'template': 'index'})
@views.route("/<template>")
def static_html(template):
    try:
        return render_template('%s.html' % template)
    except TemplateNotFound:
        page = Pages.query.filter_by(route=template).first_or_404()
        return render_template('page.html', content=markdown(page.html))


@views.route('/teams', defaults={'page': '1'})
@views.route('/teams/<int:page>')
def teams(page):
    page = abs(int(page))
    results_per_page = 50
    page_start = results_per_page * (page - 1)
    page_end = results_per_page * (page - 1) + results_per_page

    if utils.get_config('verify_emails'):
        count = Teams.query.filter_by(verified=True, banned=False).count()
        teams = Teams.query.filter_by(verified=True, banned=False).slice(page_start, page_end).all()
    else:
        count = Teams.query.filter_by(banned=False).count()
        teams = Teams.query.filter_by(banned=False).slice(page_start, page_end).all()
    pages = int(count / results_per_page) + (count % results_per_page > 0)
    return render_template('teams.html', teams=teams, team_pages=pages, curr_page=page)


@views.route('/team/<int:teamid>', methods=['GET', 'POST'])
def team(teamid):
    if utils.get_config('view_scoreboard_if_utils.authed') and not utils.authed():
        return redirect(url_for('auth.login', next=request.path))
    errors = []
    freeze = utils.get_config('freeze')
    user = Teams.query.filter_by(id=teamid).first_or_404()
    solves = Solves.query.filter_by(teamid=teamid)
    awards = Awards.query.filter_by(teamid=teamid)

    place = user.place()
    score = user.score()

    if freeze:
        freeze = utils.unix_time_to_utc(freeze)
        if teamid != session.get('id'):
            solves = solves.filter(Solves.date < freeze)
            awards = awards.filter(Awards.date < freeze)

    solves = solves.all()
    awards = awards.all()

    db.session.close()

    if utils.hide_scores() and teamid != session.get('id'):
        errors.append('分数已隐藏')

    if errors:
        return render_template('team.html', team=user, errors=errors)

    if request.method == 'GET':
        return render_template('team.html', solves=solves, awards=awards, team=user, score=score, place=place, score_frozen=utils.is_scoreboard_frozen())
    elif request.method == 'POST':
        json = {'solves': []}
        for x in solves:
            json['solves'].append({'id': x.id, 'chal': x.chalid, 'team': x.teamid})
        return jsonify(json)


@views.route('/profile', methods=['POST', 'GET'])
def profile():
    if utils.authed():
        if request.method == "POST":
            errors = []

            name = request.form.get('name')
            email = request.form.get('email')
            website = request.form.get('website')
            affiliation = request.form.get('affiliation')
            country = request.form.get('country')

            user = Teams.query.filter_by(id=session['id']).first()

            if not utils.get_config('prevent_name_change'):
                names = Teams.query.filter_by(name=name).first()
                name_len = len(request.form['name']) == 0

            emails = Teams.query.filter_by(email=email).first()
            valid_email = re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email)

            if ('password' in request.form.keys() and not len(request.form['password']) == 0) and \
                    (not bcrypt_sha256.verify(request.form.get('confirm').strip(), user.password)):
                errors.append("旧密码不匹配")
            if not valid_email:
                errors.append("不是有效的Email地址")
            if not utils.get_config('prevent_name_change') and names and name != session['username']:
                errors.append('队伍名已注册')
            if emails and emails.id != session['id']:
                errors.append('Email地址已注册')
            if not utils.get_config('prevent_name_change') and name_len:
                errors.append('队伍名字不够长')
            if website.strip() and not utils.validate_url(website):
                errors.append("不是有效的URL地址")

            if len(errors) > 0:
                return render_template('profile.html', name=name, email=email, website=website,
                                       affiliation=affiliation, country=country, errors=errors)
            else:
                team = Teams.query.filter_by(id=session['id']).first()
                if not utils.get_config('prevent_name_change'):
                    team.name = name
                if team.email != email.lower():
                    team.email = email.lower()
                    if utils.get_config('verify_emails'):
                        team.verified = False
                session['username'] = team.name

                if 'password' in request.form.keys() and not len(request.form['password']) == 0:
                    team.password = bcrypt_sha256.encrypt(request.form.get('password'))
                team.website = website
                team.affiliation = affiliation
                team.country = country
                db.session.commit()
                db.session.close()
                return redirect(url_for('views.profile'))
        else:
            user = Teams.query.filter_by(id=session['id']).first()
            name = user.name
            email = user.email
            website = user.website
            affiliation = user.affiliation
            country = user.country
            prevent_name_change = utils.get_config('prevent_name_change')
            confirm_email = utils.get_config('verify_emails') and not user.verified
            return render_template('profile.html', name=name, email=email, website=website, affiliation=affiliation,
                                   country=country, prevent_name_change=prevent_name_change, confirm_email=confirm_email)
    else:
        return redirect(url_for('auth.login'))


@views.route('/files', defaults={'path': ''})
@views.route('/files/<path:path>')
def file_handler(path):
    f = Files.query.filter_by(location=path).first_or_404()
    if f.chal:
        if not utils.is_admin():
            if not utils.ctftime():
                if utils.view_after_ctf() and utils.ctf_started():
                    pass
                else:
                    abort(403)
    upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_file(safe_join(upload_folder, f.location))


@views.route('/themes/<theme>/static/<path:path>')
def themes_handler(theme, path):
    filename = safe_join(app.root_path, 'themes', theme, 'static', path)
    if os.path.isfile(filename):
        return send_file(filename)
    else:
        abort(404)
