import statistics
import datetime
import pytz
import math
import csv

import yaml
from flask import Blueprint, render_template, request
from CTFd.models import db, Challenges, Solves, Users
from CTFd.utils import get_config
from CTFd.utils.user import get_current_user, is_admin
from CTFd.utils.decorators import authed_only, admins_only
from CTFd.cache import cache

from ..models import DiscordUsers
from ..utils import solved_challenges, module_visible, module_challenges_visible, dojo_route, DOJOS_DIR
from .writeups import WriteupComments, writeup_weeks, all_writeups
from .discord import discord_reputation


grades = Blueprint("grades", __name__)


def average(data):
    data = list(data)
    if not data:
        return 0.0
    return sum(data) / len(data)


def helpful_credit(reputation, max_reputation):
    if not reputation or not max_reputation:
        return 0.0
    return round(100 * (math.log2(reputation + 0.1) / math.log2(max_reputation + 0.1))) / 1000


def shared_helpful_extra_credit():
    students = yaml.safe_load(get_config("students"))
    student_ids = set(int(student["dojo_id"]) for student in students)

    all_reputation = discord_reputation()
    max_reputation = max(all_reputation.values(), default=None)

    discord_users = {
        discord_user.discord_id: discord_user.user_id
        for discord_user in DiscordUsers.query.all()
    }

    all_shared_credit = [
        helpful_credit(reputation, max_reputation)
        for discord_id, reputation in all_reputation.items()
        if discord_users.get(discord_id) not in student_ids
    ]

    return sum(all_shared_credit) / len(students)

def module_grade_report(dojo, module, user, when=None):
    m = { }

    challenges = solved_challenges(dojo, module, user, when=when)
    assigned = module.get("time_assigned", None)
    due = module.get("time_due", None)
    ec_full = module.get("time_ec_full", None)
    ec_part = module.get("time_ec_part", None)

    if assigned and due and not ec_full:
        ec_full = (assigned + (due-assigned)/2)
    if assigned and due and not ec_part:
        ec_part = (assigned + (due-assigned)/4)

    m['name'] = module['name']
    m['total_challenges'] = len(challenges)
    m['late_penalty'] = module.get('late_penalty', module.get('late', 0.5))
    m['time_assigned'] = assigned
    m['time_due'] = due
    m['time_ec_part'] = ec_part
    m['time_ec_full'] = ec_full

    m['solved_timely'] = 0
    m['solved_late'] = 0
    m['solved_part_ec'] = 0
    m['earned_part_ec'] = 0
    m['solved_full_ec'] = 0
    m['earned_full_ec'] = 0
    m['early_bird_ec'] = 0
    m['module_grade'] = 0

    if challenges and due and user:
        m['solved_timely'] = len([ c for c in challenges if c.solved and pytz.UTC.localize(c.solve_date) < due ])
        m['solved_late'] = len([ c for c in challenges if c.solved and pytz.UTC.localize(c.solve_date) >= due ])
        m['module_grade'] = 100 * (m['solved_timely'] + m['solved_late']*(1-m['late_penalty'])) / len(challenges)

        if ec_part:
            m['solved_part_ec'] = len([ c for c in challenges if c.solved and pytz.UTC.localize(c.solve_date) < ec_part ])
            m['earned_part_ec'] = (m['solved_part_ec'] >= len(challenges) // 4)
        if ec_full:
            m['solved_full_ec'] = len([ c for c in challenges if c.solved and pytz.UTC.localize(c.solve_date) < ec_full ])
            m['earned_full_ec'] = (m['solved_full_ec'] >= len(challenges) // 2)
        m['early_bird_ec'] = 1.0 if m['earned_full_ec'] else 0.5 if m['earned_part_ec'] else 0

    return m


def overall_grade_report(dojo, user, when=None):
    reports = [ ]
    for module in dojo.modules:
        if not module_visible(dojo, module, user) or not module_challenges_visible(dojo, module, user):
            continue
        r = module_grade_report(dojo, module, user, when=when)
        if not r['total_challenges']:
            continue
        if when and r['time_assigned'] > when:
            continue
        reports.append(r)

    module_average = statistics.mean(r["module_grade"] for r in reports)
    part_ec = sum((0.5 if r["earned_part_ec"] and not r["earned_full_ec"] else 0) for r in reports)
    full_ec = sum((1.0 if r["earned_full_ec"] else 0) for r in reports)
    ctf_ec = 0
    bug_ec = 0
    meme_ec = 0
    help_ec = 0
    total_grade = module_average + part_ec + full_ec + ctf_ec + bug_ec + meme_ec + help_ec

    return dict(
        module_reports=reports,
        module_average=module_average,
        part_ec=part_ec,
        full_ec=full_ec,
        ctf_ec=ctf_ec,
        bug_ec=bug_ec,
        help_ec=help_ec,
        meme_ec=meme_ec,
        total_grade=total_grade,
    )


@grades.route("/<dojo>/grades", methods=["GET"])
@grades.route("/<dojo>/grades/<int:user_id>", methods=["GET"])
@dojo_route
@authed_only
def view_grades(dojo, user_id=None):
    if not user_id or not is_admin():
        user = get_current_user()
    else:
        user = Users.query.filter_by(id=user_id).first()

    when = request.args.get("when", None)
    if when:
        when = pytz.UTC.localize(datetime.datetime.fromtimestamp(int(when)))

    grades = overall_grade_report(dojo=dojo, user=user, when=when)

    return render_template("grades.html", grades=grades)


@grades.route("/admin/grades/<dojo>", methods=["GET"])
@dojo_route
@admins_only
@cache.memoize(timeout=1800)
def view_all_grades(dojo):
    when = request.args.get("when")
    if when:
        when = datetime.datetime.fromtimestamp(int(when))

    student_emails = set()
    for csv_path in DOJOS_DIR.glob(f"{dojo.id}/*.csv"):
        with open(csv_path) as csv_file:
            student_emails |= set(student["Zoom Email"] for student in csv.DictReader(csv_file))

    grades = []
    for email in student_emails:
        user = Users.query.filter_by(email=email).first()
        report = overall_grade_report(dojo, user, when=when) if user else {}
        grades.append({
            "id": user.id if user else None,
            "email": email,
            "overall": report.get("total_grade"),
            **{
                module["name"]: module["module_grade"]
                for module in report.get("module_reports", [])
            }
        })

    grades.sort(key=lambda k: (k["overall"] or 0.0, -(k["id"] or float("inf"))), reverse=True)

    grade_statistics = [
        {
            "id": "Average",
            "email": "",
            **{
                name: statistics.mean(grade[name] for grade in grades if grade.get(name) is not None)
                for name in grades[0]
                if name not in ["id", "email"]
            }
        }
    ] if grades else []

    return render_template("admin_grades.html", grades=grades, grade_statistics=grade_statistics)
