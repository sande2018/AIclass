from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
# 从models导入db和模型
from models import db, User, Course, Enrollment, Section, Lesson, CompletedSection, QuizQuestion, Comment, Reply, RedemptionCode, RedemptionRecord, Order, Article, ArticleCategory, ArticleTag, article_tags, login_required, admin_required

from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
import time
import hashlib
import requests
import json
from datetime import datetime, timedelta
from functools import wraps
import jwt
from txplayer import get_tx_url
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler

# 限速
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# app.config['SECRET_KEY'] = os.urandom(24)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///education.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# 初始化 Flask-Limiter，基于 IP 进行限流
limiter = Limiter(
    get_remote_address,  # 获取客户端 IP
    app=app,
    default_limits=["120 per second"]  # 全局默认限制，每个 IP 每分钟最多 60 次请求
)

# 初始化db
db.init_app(app)

# 富友支付配置
FUIOU_CONFIG = {
    'mchnt_cd': '0005810F3853948',  # 测试环境商户号0002900F1503036
    'mchnt_key': '0f9ba620056511f0e56cf46e8782b98c',  # 测试环境密钥f00dac5077ea11e754e14c9541bc0170
    'order_prefix': '17849',  # 测试环境订单前缀1066
    'notify_url': 'https://class.gzturing.com/dashboard',  # 回调地址
    # 'api_url': '',  # 测试环境下单地址https://aipaytest.fuioupay.com/aggregatePay/preCreate
    # 'refund_url': '',  # 测试退款接口地址https://aipaytest.fuioupay.com/aggregatePay/commonRefund
    # 'query_url': '',  # 测试订单查询地址https://aipaytest.fuioupay.com/aggregatePay/commonQuery
    # 【支付宝可用】ALIPAY、ALBX(支付宝保险类)：支付宝APP扫码能直接输入密码
    # 【银联可用】UNIONPAY(云闪付)：云闪付APP扫码能直接输入密码
    # 请求功能尚不支持：ALIAPP、 WXAPP、 WXH5、ALIH5
    # 系统内部错误：WXBX、WXXS、WECHAT
    'order_type': "WECHAT",
    'api_url': 'https://aipay-fzg.fuioupay.com/aggregatePay/preCreate',  # 运营生产环境地址
    'refund_url': ' https://aipay-fzg.fuioupay.com/aggregatePay/commonRefund',  # 运营退款接口地址
    'query_url': 'https://aipay-fzg.fuioupay.com/aggregatePay/commonQuery',  # 运营订单查询地址
    'APPID': 'wxfa089da95020ba1a',  # wx5ac8eb4651fe544f 调用2.16接口获取openid即可。
}


scheduler = BackgroundScheduler()
scheduler.start()

# 定义检测订单状态的函数
# 定时任务：检测并处理 pending 状态的订单
def check_and_process_pending_orders():
    with app.app_context():  # 创建应用上下文
        # print("开始检测订单状态...")
        try:
            pending_orders = Order.query.filter_by(status='pending').all()
            if pending_orders:
                print(f"检测到 {len(pending_orders)} 个未完成的订单，正在处理...")
                for order in pending_orders:
                    # 检查订单是否超时（5分钟后）
                    if is_order_timeout(order.created_at):
                        order.status = "failed"
                        db.session.commit()
                        print(f"订单 {order.order_no} 超时未支付，状态已更新为 'failed'")
                    else:
                        print(f"订单 {order.order_no} 仍在等待支付...")
                        # 调用富友支付的订单查询接口
                        query_result = query_fuiou_payment_status(order)
                        if query_result:
                            # 根据查询结果更新订单状态
                            if query_result['status'] == 'completed':
                                order.status = 'completed'
                                order.transaction_id = query_result.get('transaction_id')
                                order.paid_at = datetime.now()
                                db.session.commit()
                                payment_notify(order.order_no, order.transaction_id)



                                print(f"订单 {order.order_no} 已支付，状态已更新为 'completed'")

                            elif query_result['status'] == 'failed':
                                order.status = 'failed'
                                db.session.commit()
                                print(f"订单 {order.order_no} 支付失败，状态已更新为 'failed'")
            else:
                pass
                # print("没有未完成的订单。")
        except Exception as e:
            print(f"处理订单状态时出错: {str(e)}")
            import traceback
            print(traceback.format_exc())

def is_order_timeout(created_at,tiqian=0):
    """判断订单是否超时（30分钟后）"""
    now = datetime.now()
    timeout_delta = timedelta(minutes=30-tiqian)
    return (now - created_at) > timeout_delta


def query_fuiou_payment_status(order):
    """调用富友支付的订单查询接口"""
    # 准备请求参数
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    params = {
        'version': '1.0',
        'mchnt_cd': FUIOU_CONFIG['mchnt_cd'],
        'random_str': random_str,
        'order_type': order.payment_method,
        'mchnt_order_no': order.order_no,
        'term_id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
    }

    # 生成签名
    sign_str = (
        f"{params['mchnt_cd']}|"
        f"{params['order_type']}|"
        f"{params['mchnt_order_no']}|"
        f"{params['term_id']}|"
        f"{params['random_str']}|"
        f"{params['version']}|"
        f"{FUIOU_CONFIG['mchnt_key']}"
    )
    params['sign'] = hashlib.md5(sign_str.encode()).hexdigest()

    try:
        # 发送请求到富友支付查询接口
        response = requests.post(FUIOU_CONFIG['query_url'], json=params)
        result = response.json()

        if result.get('result_code') == '000000':
            # 解析查询结果
            status = result.get('trans_stat')
            transaction_id = result.get('transaction_id')

            # 将富友支付的状态映射到我们的系统状态
            if status == 'SUCCESS':
                return {
                    'status': 'completed',
                    'transaction_id': transaction_id,
                    # 添加其他可能需要的参数
                    'txn_fin_ts': result.get('txn_fin_ts'),  # 支付完成时间
                    'reserved_fy_settle_dt': result.get('reserved_fy_settle_dt'),  # 富友清算日
                    'reserved_buyer_logon_id': result.get('reserved_buyer_logon_id'),  # 买家登录账号
                    'reserved_fund_bill_list': result.get('reserved_fund_bill_list'),  # 渠道信息
                    'reserved_fy_trace_no': result.get('reserved_fy_trace_no'),  # 富友追踪号
                    'reserved_channel_order_id': result.get('reserved_channel_order_id'),  # 银行交易号
                }
            elif status in ['NOTPAY', 'USERPAYING']:
                return {'status': 'pending'}
            else:
                return {'status': 'failed'}
        else:
            print(f"查询支付状态失败: {result.get('result_code')} - {result.get('result_msg')}")
            return None
    except Exception as e:
        print(f"查询支付状态异常: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return None


# 装饰器：检查用户是否登录
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录。', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# 装饰器：检查用户是否是管理员
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录。', 'warning')
            return redirect(url_for('admin_login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('您没有权限访问此页面。', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated_function


# 图标
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


# 路由
@app.route('/')
def index():
    # 获取所有课程以在首页显示热门课程
    all_courses = Course.query.filter_by(is_published=True).all()

    # 获取用户已报名的课程ID列表
    enrolled_course_ids = []
    if 'user_id' in session:
        user_enrollments = Enrollment.query.filter_by(user_id=session['user_id']).all()
        enrolled_course_ids = [enrollment.course_id for enrollment in user_enrollments]

    return render_template('index.html', courses=all_courses, enrolled_course_ids=enrolled_course_ids)


# 自定义限速错误处理器
@app.errorhandler(429)
def custom_rate_limit_error(e):
    # 返回自定义的响应内容，而不是默认的 Too Many Requests
    return jsonify({"message": "请求过于频繁，请稍后再试"}), 429



# 修改登录路由，支持用户名/手机号/邮箱登录
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("120 per minute")
def login():
    if request.method == 'POST':
        account = request.form.get('account')  # 改为account，可以是用户名、邮箱或手机号
        password = request.form.get('password')

        # 查找用户（通过用户名、邮箱或手机号）
        user = User.query.filter(
            db.or_(
                User.username == account,
                User.email == account,
                User.phone == account
            )
        ).first()

        if user and check_password_hash(user.password, password) and user.is_active:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            # 更新最后登录时间
            user.last_login = datetime.now()
            db.session.commit()

            flash('登录成功！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('账户或密码错误，或账号已被禁用。', 'danger')
            return render_template('login.html')

    # 添加这一行，处理GET请求
    return render_template('login.html')


# 修改注册路由，处理手机号字段并验证
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        # 验证手机号和邮箱至少有一个
        if not email and not phone:
            flash('邮箱和手机号至少填写一项。', 'danger')
            return render_template('register.html')

        # 检查用户名是否已存在
        existing_username = User.query.filter(User.username == username).first()
        if existing_username:
            flash('用户名已被注册。', 'danger')
            return render_template('register.html')

        # 检查邮箱是否已存在（如果提供了邮箱）
        if email:
            existing_email = User.query.filter(User.email == email).first()
            if existing_email:
                flash('邮箱已被注册。', 'danger')
                return render_template('register.html')

        # 检查手机号是否已存在（如果提供了手机号）
        if phone:
            existing_phone = User.query.filter(User.phone == phone).first()
            if existing_phone:
                flash('手机号已被注册。', 'danger')
                return render_template('register.html')

        # 创建新用户
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email if email and email.strip() else None,
            phone=phone if phone and phone.strip() else None,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        flash('注册成功！请登录。', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# 处理头像更新
@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    user_id = session['user_id']
    avatar = request.form.get('avatar')

    # Validate avatar selection
    if not avatar or not avatar.startswith('avatar_') or not avatar.endswith('.svg'):
        return jsonify({'success': False, 'message': '无效的头像选择'})

    # Update user avatar
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'})

    user.avatar = avatar
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '头像更新成功',
        'avatar_url': url_for('static', filename=f'images/avatar_imgs/{avatar}')
    })


# 个人中心
@app.route('/dashboard')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    enrollments = Enrollment.query.filter_by(user_id=user.id).all()
    enrolled_courses = [(enrollment.course, enrollment.progress) for enrollment in enrollments]

    # 获取用户订单
    user_orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()

    # Get the avatar URL
    avatar_url = url_for('static', filename=f'images/avatar_imgs/{user.avatar}')

    return render_template('dashboard.html', user=user, courses=enrolled_courses, avatar_url=avatar_url,
                           orders=user_orders)


# 添加账号设置路由
@app.route('/account_settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    success_message = None

    if request.method == 'POST':
        # 获取表单数据
        phone = request.form.get('phone')
        email = request.form.get('email')
        password = request.form.get('password')

        # 验证手机号和邮箱至少有一个
        if not email and not phone:
            flash('邮箱和手机号至少填写一项。', 'danger')
            return redirect(url_for('account_settings'))

        # 检查手机号是否已被其他用户使用
        if phone and phone != user.phone:
            existing_phone = User.query.filter(User.phone == phone, User.id != user.id).first()
            if existing_phone:
                flash('手机号已被其他用户使用。', 'danger')
                return redirect(url_for('account_settings'))

        # 检查邮箱是否已被其他用户使用
        if email and email != user.email:
            existing_email = User.query.filter(User.email == email, User.id != user.id).first()
            if existing_email:
                flash('邮箱已被其他用户使用。', 'danger')
                return redirect(url_for('account_settings'))

        # 更新用户信息
        user.phone = phone if phone else None
        user.email = email if email else None

        # 如果提供了新密码，则更新密码
        if password:
            user.password = generate_password_hash(password)

        db.session.commit()
        success_message = '账号信息更新成功！'

    # 获取头像URL
    avatar_url = url_for('static', filename=f'images/avatar_imgs/{user.avatar}')

    return render_template('account_settings.html',
                           user=user,
                           avatar_url=avatar_url,
                           success_message=success_message)


@app.route('/courses')
def courses():
    all_courses = Course.query.filter_by(is_published=True).all()

    # 获取用户已报名的课程ID列表
    enrolled_course_ids = []
    if 'user_id' in session:
        user_enrollments = Enrollment.query.filter_by(user_id=session['user_id']).all()
        enrolled_course_ids = [enrollment.course_id for enrollment in user_enrollments]

    return render_template('courses.html', courses=all_courses, enrolled_course_ids=enrolled_course_ids)


@app.route('/course/<int:course_id>')
@login_required
def course_content(course_id):
    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在。', 'warning')
        return redirect(url_for('courses'))
    user = db.session.get(User, session['user_id'])

    # 检查用户是否已注册该课程
    enrollment = Enrollment.query.filter_by(user_id=user.id, course_id=course.id).first()
    if not enrollment:
        flash('您尚未注册此课程。', 'warning')
        return redirect(url_for('courses'))

    # 获取课程章节，按顺序排列
    sections = Section.query.filter_by(course_id=course.id).order_by(Section.order).all()
    video_urls = {}
    # 处理每个章节的视频 URL

    for section in sections:
        video_urls[section.id] = get_tx_url(section.video_url) #if "vod-qcloud.com||" in section.video_url else section.video_url
    # print(video_urls)
    # for section in sections:
    #     if "vod-qcloud.com||" in section.video_url:
    #         video_urls[section.id] = get_tx_url(section.video_url)
    #     else:
    #         video_urls[section.id] = section.video_url  # 保持原始 URL

    # 获取已完成的章节
    completed_sections = CompletedSection.query.filter_by(enrollment_id=enrollment.id).all()
    completed_section_ids = [cs.section_id for cs in completed_sections]

    # 为每个章节添加completed属性
    for section in sections:
        section.completed = section.id in completed_section_ids

        # 获取章节评论
        # 如果是管理员，获取所有评论；否则，获取公开评论和用户自己的评论
        if user.is_admin:
            comments = Comment.query.filter_by(section_id=section.id).order_by(Comment.created_at.desc()).all()
        else:
            comments = Comment.query.filter(
                Comment.section_id == section.id,
                db.or_(
                    Comment.visibility == 'public',
                    db.and_(Comment.visibility == 'admin_self', Comment.user_id == user.id),
                    db.and_(Comment.visibility == 'self', Comment.user_id == user.id)
                )
            ).order_by(Comment.created_at.desc()).all()

        # 为每个评论添加用户信息和回复
        # section.comments = []
        for comment in comments:
            comment_user = db.session.get(User, comment.user_id)
            comment_data = {
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M'),
                'visibility': comment.visibility,
                'user': {
                    'id': comment_user.id,
                    'username': comment_user.username
                },
                'replies': []
            }

            # 获取评论的回复
            replies = Reply.query.filter_by(comment_id=comment.id).order_by(Reply.created_at).all()
            for reply in replies:
                reply_user = db.session.get(User, reply.user_id)
                reply_data = {
                    'id': reply.id,
                    'content': reply.content,
                    'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
                    'user': {
                        'id': reply_user.id,
                        'username': reply_user.username
                    }
                }
                comment_data['replies'].append(reply_data)

            section.comments_data = []
            for comment in comments:
                comment_user = db.session.get(User, comment.user_id)
                comment_data = {
                    'id': comment.id,
                    'content': comment.content,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M'),
                    'visibility': comment.visibility,
                    'user': {
                        'id': comment_user.id,
                        'username': comment_user.username
                    },
                    'replies': []
                }

                # 获取评论的回复
                replies = Reply.query.filter_by(comment_id=comment.id).order_by(Reply.created_at).all()
                for reply in replies:
                    reply_user = db.session.get(User, reply.user_id)
                    reply_data = {
                        'id': reply.id,
                        'content': reply.content,
                        'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
                        'user': {
                            'id': reply_user.id,
                            'username': reply_user.username
                        }
                    }
                    comment_data['replies'].append(reply_data)

                section.comments_data.append(comment_data)  # 使用一个普通列表

    # 计算进度
    progress = 0
    if sections:
        progress = int((len(completed_section_ids) / len(sections)) * 100)
        # 更新  课记录中的进度
        enrollment.progress = progress
        if progress == 100:
            enrollment.is_completed = True
        db.session.commit()

    # 计算总时长
    total_duration = sum(section.duration for section in sections)

    # 格式化注册日期
    enrollment_date = enrollment.enrollment_date.strftime('%Y-%m-%d')

    return render_template('course_content.html',
                           course=course,
                           sections=sections,
                           video_urls=video_urls,
                           progress=progress,
                           total_duration=total_duration,
                           enrollment_date=enrollment_date,
                           current_user=user)


@app.route('/mark_complete/<int:course_id>/<int:section_id>', methods=['POST'])
@login_required
def mark_complete(course_id, section_id):
    user_id = session['user_id']

    # 获取选课记录
    enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
    if not enrollment:
        return jsonify({'success': False, 'message': '您尚未注册此课程'}), 400

    # 检查章节是否已完成
    completed = CompletedSection.query.filter_by(enrollment_id=enrollment.id, section_id=section_id).first()
    if not completed:
        # 标记章节为已完成
        completed_section = CompletedSection(enrollment_id=enrollment.id, section_id=section_id)
        db.session.add(completed_section)
        db.session.commit()

    # 重新计算进度
    sections_count = Section.query.filter_by(course_id=course_id).count()
    completed_count = CompletedSection.query.filter_by(enrollment_id=enrollment.id).count()

    progress = int((completed_count / sections_count) * 100) if sections_count > 0 else 0

    # 更新选课记录
    enrollment.progress = progress
    if progress == 100:
        enrollment.is_completed = True
    db.session.commit()

    return jsonify({'success': True, 'progress': progress})


@app.route('/complete_course/<int:course_id>', methods=['POST'])
@login_required
def complete_course(course_id):
    user_id = session['user_id']

    # 获取选课记录
    enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
    if not enrollment:
        return jsonify({'success': False, 'message': '您尚未注册此课程'}), 400

    # 标记课程为已完成
    enrollment.is_completed = True
    enrollment.progress = 100
    db.session.commit()

    return jsonify({'success': True})


# 更新添加评论的路由
@app.route('/add_comment/<int:course_id>/<int:section_id>', methods=['POST'])
@login_required
def add_comment_section(course_id, section_id):
    user_id = session['user_id']
    data = request.get_json()
    print("收到的评论数据:", data)
    content = data.get('content')
    visibility = data.get('visibility', 'public')  # 默认为公开

    if not content:
        return jsonify({'success': False, 'message': '评论内容不能为空'}), 400

    # 创建新评论
    comment = Comment(
        user_id=user_id,
        course_id=course_id,
        section_id=section_id,
        content=content,
        visibility=visibility
    )
    db.session.add(comment)
    db.session.commit()

    # 获取用户信息
    # user = User.query.get(user_id)
    user = db.session.get(User, user_id)

    # 返回评论数据
    return jsonify({
        'success': True,
        'comment': {
            'id': comment.id,
            'content': comment.content,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M'),
            'username': user.username,
            'user_id': user.id,
            'visibility': comment.visibility,
            'user_avatar': user.avatar  # 使用用户的实际头像
        }
    })


# 添加回复评论的路由
@app.route('/add_reply/<int:course_id>/<int:section_id>/<int:comment_id>', methods=['POST'])
@login_required
def add_reply(course_id, section_id, comment_id):
    user_id = session['user_id']
    data = request.get_json()
    content = data.get('content')

    if not content:
        return jsonify({'success': False, 'message': '回复内容不能为空'}), 400

    # 检查评论是否存在
    comment = Comment.query.get(comment_id)
    if not comment or comment.section_id != section_id or comment.course_id != course_id:
        return jsonify({'success': False, 'message': '评论不存在'}), 404

    # 创建新回复
    reply = Reply(comment_id=comment_id, user_id=user_id, content=content)
    db.session.add(reply)
    db.session.commit()

    # 获取用户信息
    user = User.query.get(user_id)

    # 返回回复数据
    return jsonify({
        'success': True,
        'reply': {
            'id': reply.id,
            'content': reply.content,
            'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
            'username': user.username,
            'user_id': user.id,
            'user_avatar': user.avatar  # 使用用户的实际头像
        }
    })


# 删除评论的路由
@app.route('/delete_comment/<int:course_id>/<int:section_id>/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(course_id, section_id, comment_id):
    user_id = session['user_id']

    # 获取评论
    comment = Comment.query.get(comment_id)
    if not comment or comment.section_id != section_id or comment.course_id != course_id:
        return jsonify({'success': False, 'message': '评论不存在'}), 404

    # 检查权限（只有评论作者或管理员可以删除）
    user = User.query.get(user_id)
    if comment.user_id != user_id and not user.is_admin:
        return jsonify({'success': False, 'message': '没有权限删除此评论'}), 403

    # 删除评论
    db.session.delete(comment)
    db.session.commit()

    return jsonify({'success': True})


# 删除回复的路由
@app.route('/delete_reply/<int:course_id>/<int:section_id>/<int:reply_id>', methods=['DELETE'])
@login_required
def delete_reply(course_id, section_id, reply_id):
    user_id = session['user_id']

    # 获取回复
    reply = Reply.query.get(reply_id)
    if not reply:
        return jsonify({'success': False, 'message': '回复不存在'}), 404

    # 检查评论是否属于指定章节和课程
    comment = Comment.query.get(reply.comment_id)
    if not comment or comment.section_id != section_id or comment.course_id != course_id:
        return jsonify({'success': False, 'message': '回复不存在'}), 404

    # 检查权限（只有回复作者或管理员可以删除）
    user = User.query.get(user_id)
    if reply.user_id != user_id and not user.is_admin:
        return jsonify({'success': False, 'message': '没有权限删除此回复'}), 403

    # 删除回复
    db.session.delete(reply)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/add_comment/<int:course_id>', methods=['POST'])
@login_required
def add_comment(course_id):
    user_id = session['user_id']
    data = request.get_json()
    content = data.get('content')

    if not content:
        return jsonify({'success': False, 'message': '评论内容不能为空'}), 400

    # 创建新评论
    comment = Comment(user_id=user_id, course_id=course_id, section_id=0, content=content)
    db.session.add(comment)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/submit_quiz/<int:course_id>/<int:section_id>', methods=['POST'])
@login_required
def submit_quiz(course_id, section_id):
    user_id = session['user_id']
    data = request.get_json()
    answers = data.get('answers', {})

    # 获取选课记录
    enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
    if not enrollment:
        return jsonify({'success': False, 'message': '您尚未注册此课程'}), 400

    # 获取测验题目
    questions = QuizQuestion.query.filter_by(section_id=section_id).all()

    # 计算得分
    score = 0
    total = len(questions)

    for question in questions:
        question_key = f'question-{question.id}'
        if question_key in answers and int(answers[question_key]) == question.correct_answer:
            score += 1

    # 记录测验分数
    completed_section = CompletedSection.query.filter_by(enrollment_id=enrollment.id, section_id=section_id).first()
    if not completed_section:
        completed_section = CompletedSection(enrollment_id=enrollment.id, section_id=section_id, quiz_score=score)
        db.session.add(completed_section)
    else:
        completed_section.quiz_score = score

    db.session.commit()

    # 判断是否通过测验（60%及格）
    passed = (score / total) >= 0.6 if total > 0 else False

    return jsonify({
        'success': True,
        'score': score,
        'total': total,
        'passed': passed
    })


@app.route('/enroll/<int:course_id>')
@login_required
def enroll(course_id):
    # 获取课程信息
    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在', 'danger')
        return redirect(url_for('courses'))

    # 检查是否已经注册该课程
    existing_enrollment = Enrollment.query.filter_by(
        user_id=session['user_id'],
        course_id=course_id
    ).first()

    if existing_enrollment:
        flash('您已经注册了这门课程。', 'info')
        return redirect(url_for('dashboard'))

    # 检查课程是否需要付费
    if course.price > 0:
        # 付费课程需要通过兑换码注册或购买
        return redirect(url_for('purchase', course_id=course_id))
    else:
        # 免费课程直接注册
        new_enrollment = Enrollment(user_id=session['user_id'], course_id=course_id)
        db.session.add(new_enrollment)
        db.session.commit()
        flash('课程注册成功！', 'success')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('index'))


@app.route('/get_video_url/<int:section_id>')
@login_required
def get_video_url(section_id):
    # Get the section
    section = db.session.get(Section, section_id)
    if not section:
        return jsonify({'success': False, 'message': '章节不存在'})

    # Check if user is enrolled in this course
    user_id = session['user_id']
    enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=section.course_id).first()
    if not enrollment:
        return jsonify({'success': False, 'message': '您尚未注册此课程'})

    # 处理视频URL
    # video_url = ""
    video_url = get_tx_url(section.video_url)


    return jsonify({
        'success': True,
        'video_url': video_url
    })


# 购买相关路由
@app.route('/purchase/<int:course_id>')
def purchase(course_id):
    # 获取课程信息
    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在', 'danger')
        return redirect(url_for('courses'))

    # 检查是否已经注册该课程
    if 'user_id' in session:
        existing_enrollment = Enrollment.query.filter_by(
            user_id=session['user_id'],
            course_id=course_id
        ).first()

        if existing_enrollment:
            flash('您已经注册了这门课程。', 'info')
            return redirect(url_for('dashboard'))

    return render_template('purchase.html', course=course)


@app.route('/api/create_temp_user', methods=['POST'])
def create_temp_user():
    data = request.json
    username = data.get('username')
    phone = data.get('phone')
    course_id = data.get('course_id')

    if not username or not phone or not course_id:
        return jsonify({'success': False, 'message': '缺少必要参数'})

    # 检查手机号是否已存在
    existing_user = User.query.filter_by(phone=phone).first()
    if existing_user:
        # 如果用户已存在，直接使用该用户
        return jsonify({'success': True, 'user_id': existing_user.id})
    else:
        # 检查用户名是否已存在，如果存在则添加随机数字
        original_username = username
        while User.query.filter_by(username=username).first():
            # 生成3位随机数字
            random_suffix = ''.join(random.choices(string.digits, k=3))
            username = f"{original_username}{random_suffix}"

        # 创建新用户
        hashed_password = generate_password_hash(phone[-6:])  # 使用手机号后6位作为初始密码
        new_user = User(
            username=username,
            phone=phone,
            password=hashed_password,
            created_at=datetime.now()
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'success': True, 'user_id': new_user.id})


@app.route('/api/create_payment', methods=['POST'])
def create_payment():
    data = request.json
    course_id = data.get('course_id')
    user_id = data.get('user_id') or session.get('user_id')

    if not course_id or not user_id:
        return jsonify({'success': False, 'message': '缺少必要参数'})

    course = db.session.get(Course, course_id)
    if not course:
        return jsonify({'success': False, 'message': '课程不存在'})

    # 生成订单号 (使用测试环境订单前缀)
    order_no = f"{FUIOU_CONFIG['order_prefix']}{int(time.time())}{random.randint(1000, 9999)}"
    # 创建订单记录
    amount = int(course.price * 100)  # 转换为分
    new_order = Order(
        order_no=order_no,
        user_id=user_id,
        course_id=course_id,
        amount=amount,
        status='pending',
        payment_method=FUIOU_CONFIG['order_type'],  # 默认支付方式
        ip_address=request.remote_addr,
        created_at=datetime.now()
    )
    db.session.add(new_order)
    db.session.commit()

    # 调用富友支付接口
    payment_url = create_fuiou_payment(order_no, course, user_id)

    if payment_url:
        return jsonify({'success': True, 'payment_url': payment_url, 'order_id': new_order.order_no})
    else:
        # 更新订单状态为失败
        new_order.status = 'failed'
        db.session.commit()
        return jsonify({'success': False, 'message': '创建支付订单失败'})


# 创建富掌柜支付订单
def create_fuiou_payment(order_no, course, user_id):
    """创建富友支付订单"""
    # 准备请求参数
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    current_time = datetime.now().strftime('%Y%m%d%H%M%S')

    amount = int(course.price * 100)  # 转换为分

    params = {
        'version': '1.0',
        'mchnt_cd': FUIOU_CONFIG['mchnt_cd'],
        'random_str': random_str,
        'order_type': FUIOU_CONFIG['order_type'],  # 可以根据需要选择支付方式
        'order_amt': str(amount),
        'mchnt_order_no': order_no,
        'txn_begin_ts': current_time,
        'goods_des': course.title,
        'term_id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
        'term_ip': request.remote_addr,
        'notify_url': FUIOU_CONFIG['notify_url'],
    }

    # 生成签名
    sign_str = (
        f"{params['mchnt_cd']}|{params['order_type']}|{params['order_amt']}|"
        f"{params['mchnt_order_no']}|{params['txn_begin_ts']}|{params['goods_des']}|"
        f"{params['term_id']}|{params['term_ip']}|{params['notify_url']}|"
        f"{params['random_str']}|{params['version']}|{FUIOU_CONFIG['mchnt_key']}"
    )
    params['sign'] = hashlib.md5(sign_str.encode()).hexdigest()

    try:
        # 发送请求到富友支付接口
        print("发送支付请求参数:", params)
        response = requests.post(FUIOU_CONFIG['api_url'], json=params)
        print("支付接口响应:", response.text)
        result = response.json()

        if result.get('result_code') == '000000':
            # 支付成功，返回二维码链接
            return result.get('qr_code')
        else:
            print(f"支付创建失败: {result.get('result_code')} - {result.get('result_msg')}")
            return None
    except Exception as e:
        print(f"支付请求异常: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return None


@app.route('/api/check_payment_status/<string:order_no>')
def check_payment_status(order_no):
    # 创建应用上下文
    with app.app_context():
        # 查询订单
        order = Order.query.filter_by(order_no=order_no).first()

        now = datetime.now()
        timeout_delta = timedelta(minutes=10)

        if not order:
            return jsonify({'success': False, 'message': '订单不存在'})


        if is_order_timeout(order.created_at, tiqian=5):
            return jsonify({'success': False, 'status': "failed"})
        # 返回订单状态
        return jsonify({'success': True, 'status': order.status})

# 更新支付通知处理函数，添加更多日志
def payment_notify(order_no, transaction_id, query_result=None):
    try:
        # 创建应用上下文
        with app.app_context():
            order = Order.query.filter_by(order_no=order_no).first()

            if not order:
                print(f"⚠️ 订单 {order_no} 未找到!")
                return "FAIL"

            print(f"✅ 订单 {order_no} 当前状态: {order.status}")

            # 只有支付成功时才更新订单状态
            if order.status == "completed" and order.transaction_id:
                # order.status = "completed"
                order.transaction_id = transaction_id
                order.paid_at = datetime.now()

                # 如果 query_result 中有更多参数，可以在这里更新订单的其他字段
                if query_result:
                    # 示例：更新支付完成时间
                    if 'txn_fin_ts' in query_result:
                        order.paid_at = datetime.strptime(query_result['txn_fin_ts'], '%Y%m%d%H%M%S')
                    # 可以根据需要添加其他字段的更新

                # 自动为用户添加课程
                if not Enrollment.query.filter_by(user_id=order.user_id, course_id=order.course_id).first():
                    new_enrollment = Enrollment(
                        user_id=order.user_id,
                        course_id=order.course_id,
                        enrollment_date=datetime.now()
                    )
                    db.session.add(new_enrollment)

                db.session.commit()

                print(f"✅ 订单 {order_no} 已更新为已支付并课程已添加")
            #从数据库获取该学员报名的课程名称、手机号、用户名（从数据库中读取内容）
            course_name = Course.query.get(order.course_id).title
            phone_number = User.query.get(order.user_id).phone
            name = User.query.get(order.user_id).username
            ems.send_sms(phone_number, name, course_name, kw={
                "订单号": order_no
            })

            return "1"
    except Exception as e:
        print(f"❌ 处理支付回调出错: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return "FAIL"

# 管理后台路由
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username, is_admin=True).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            # 更新最后登录时间
            user.last_login = datetime.now()
            db.session.commit()

            flash('管理员登录成功！', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('用户名或密码错误，或您不是管理员。', 'danger')

    return render_template('admin/login.html')


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # 统计数据
    stats = {
        'user_count': User.query.count(),
        'course_count': Course.query.count(),
        'enrollment_count': Enrollment.query.count(),
        'active_users_today': User.query.filter(User.last_login >= datetime.now() - timedelta(days=1)).count(),
        'total_orders': Order.query.count(),
        'completed_orders': Order.query.filter_by(status='completed').count(),
        'total_revenue': sum(order.amount for order in Order.query.filter_by(status='completed').all()) / 100  # 转换为元
    }

    # 最近选课
    recent_enrollments = Enrollment.query.order_by(Enrollment.enrollment_date.desc()).limit(5).all()

    # 热门课程
    popular_courses = db.session.query(
        Course,
        db.func.count(Enrollment.id).label('enrollment_count')
    ).join(Enrollment).group_by(Course.id).order_by(db.desc('enrollment_count')).limit(5).all()

    # 最近订单
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()

    # 格式化为前端需要的数据结构
    popular_courses_data = [
        {'title': course.title, 'enrollment_count': count}
        for course, count in popular_courses
    ]

    return render_template('admin/dashboard.html',
                           active_page='dashboard',
                           stats=stats,
                           recent_enrollments=recent_enrollments,
                           popular_courses=popular_courses_data,
                           recent_orders=recent_orders,
                           now=datetime.now())


@app.route('/admin/users')
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    users = User.query.paginate(page=page, per_page=per_page, error_out=False)

    pagination = {
        'page': users.page,
        'pages': users.pages,
        'total': users.total,
        'has_prev': users.has_prev,
        'has_next': users.has_next
    }
    print()
    return render_template('admin/users.html',
                           active_page='users',
                           users=users.items,
                           pagination=pagination)


@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')  # 添加手机号字段
    password = request.form.get('password')
    is_active = 'is_active' in request.form
    is_admin = 'is_admin' in request.form

    # 验证手机号和邮箱至少有一个
    if not email and not phone:
        flash('邮箱和手机号至少填写一项。', 'danger')
        return redirect(url_for('admin_users'))

    # 检查用户名是否已存在
    existing_username = User.query.filter(User.username == username).first()
    if existing_username:
        flash('用户名已被注册。', 'danger')
        return redirect(url_for('admin_users'))

    # 检查邮箱是否已存在（如果提供了邮箱）
    if email:
        existing_email = User.query.filter(User.email == email).first()
        if existing_email:
            flash('邮箱已被注册。', 'danger')
            return redirect(url_for('admin_users'))

    # 检查手机号是否已存在（如果提供了手机号）
    if phone:
        existing_phone = User.query.filter(User.phone == phone).first()
        if existing_phone:
            flash('手机号已被注册。', 'danger')
        return redirect(url_for('admin_users'))

    # 创建新用户
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username,
        email=email if email and email.strip() else None,
        phone=phone if phone and phone.strip() else None,
        password=hashed_password,
        is_active=is_active,
        is_admin=is_admin
    )
    db.session.add(new_user)
    db.session.commit()

    flash('用户添加成功！', 'success')
    return redirect(url_for('admin_users'))


# 修改编辑用户的管理员路由，处理手机号字段
@app.route('/admin/edit_user', methods=['POST'])
@admin_required
def admin_edit_user():
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')  # 添加手机号字段
    password = request.form.get('password')
    is_active = 'is_active' in request.form
    is_admin = 'is_admin' in request.form

    user = db.session.get(User, user_id)
    if not user:
        flash('用户不存在。', 'danger')
        return redirect(url_for('admin_users'))

    # 验证手机号和邮箱至少有一个
    if not email and not phone:
        flash('邮箱和手机号至少填写一项。', 'danger')
        return redirect(url_for('admin_users'))

    # 检查用户名是否已被其他用户使用
    existing_user = User.query.filter(User.username == username, User.id != user.id).first()
    if existing_user:
        flash('用户名已被其他用户使用。', 'danger')
        return redirect(url_for('admin_users'))

    # 检查邮箱是否已被其他用户使用（如果提供了邮箱）
    if email:
        existing_email = User.query.filter(User.email == email, User.id != user.id).first()
        if existing_email:
            flash('邮箱已被其他用户使用。', 'danger')
            return redirect(url_for('admin_users'))

    # 检查手机号是否已被其他用户使用（如果提供了手机号）
    if phone:
        existing_phone = User.query.filter(User.phone == phone, User.id != user.id).first()
        if existing_phone:
            flash('手机号已被其他用户使用。', 'danger')
            return redirect(url_for('admin_users'))

    # 更新用户信息
    user.username = username
    # 处理空字符串，转换为None以避免唯一约束问题
    user.email = email if email.strip() else None
    user.phone = phone if phone and phone.strip() else None
    if password:  # 如果提供了新密码
        user.password = generate_password_hash(password)
    user.is_active = is_active
    user.is_admin = is_admin

    db.session.commit()

    flash('用户信息更新成功！', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    user_id = request.form.get('user_id')

    # 不允许删除自己
    if int(user_id) == session['user_id']:
        flash('不能删除当前登录的管理员账号。', 'danger')
        return redirect(url_for('admin_users'))

    user = db.session.get(User, user_id)
    if not user:
        flash('用户不存在。', 'danger')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()

    flash('用户删除成功！', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/courses')
@admin_required
def admin_courses():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 修改查询，使用 db.func.count(db.distinct(Section.id)) 而不是 distinct(Section.id)
    courses_with_counts = db.session.query(
        Course,
        db.func.count(db.distinct(Section.id)).label('section_count'),
        db.func.count(db.distinct(Enrollment.id)).label('enrollment_count')
    ).outerjoin(Section).outerjoin(Enrollment).group_by(Course.id).paginate(page=page, per_page=per_page,error_out=False)


    # 格式化为前端需要的数据结构
    courses_data = []
    for course, section_count, enrollment_count in courses_with_counts.items:
        course_data = course.__dict__.copy()
        course_data['section_count'] = section_count
        course_data['enrollment_count'] = enrollment_count
        courses_data.append(course_data)

    pagination = {
        'page': courses_with_counts.page,
        'pages': courses_with_counts.pages,
        'total': courses_with_counts.total,
        'has_prev': courses_with_counts.has_prev,
        'has_next': courses_with_counts.has_next
    }

    return render_template('admin/courses.html',
                           active_page='courses',
                           courses=courses_data,
                           pagination=pagination)


@app.route('/admin/add_course', methods=['POST'])
@admin_required
def admin_add_course():
    title = request.form.get('title')
    description = request.form.get('description')
    instructor = request.form.get('instructor')
    image = request.form.get('image')
    price = request.form.get('price', type=float, default=0.0)  # 添加价格
    is_published = 'is_published' in request.form

    # 创建新课程
    new_course = Course(
        title=title,
        description=description,
        instructor=instructor,
        image=image,
        price=price,  # 添加价格
        is_published=is_published
    )
    db.session.add(new_course)
    db.session.commit()

    flash('课程添加成功！', 'success')
    return redirect(url_for('admin_courses'))


@app.route('/admin/edit_course', methods=['POST'])
@admin_required
def admin_edit_course():
    course_id = request.form.get('course_id')
    title = request.form.get('title')
    description = request.form.get('description')
    instructor = request.form.get('instructor')
    image = request.form.get('image')
    price = request.form.get('price', type=float, default=0.0)  # 添加价格
    is_published = 'is_published' in request.form

    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在。', 'danger')
        return redirect(url_for('admin_courses'))

    # 更新课程信息
    course.title = title
    course.description = description
    course.instructor = instructor
    course.image = image
    course.price = price  # 添加价格
    course.is_published = is_published
    course.updated_at = datetime.now()

    db.session.commit()

    flash('课程信息更新成功！', 'success')
    return redirect(url_for('admin_courses'))


@app.route('/admin/delete_course', methods=['POST'])
@admin_required
def admin_delete_course():
    course_id = request.form.get('course_id')

    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在。', 'danger')
        return redirect(url_for('admin_courses'))
    db.session.delete(course)
    db.session.commit()

    flash('课程删除成功！', 'success')
    return redirect(url_for('admin_courses'))


@app.route('/admin/course_content/<int:course_id>')
@admin_required
def admin_course_content(course_id):
    course = db.session.get(Course, course_id)
    if not course:
        flash('课程不存在。', 'danger')
        return redirect(url_for('admin_courses'))
    sections = Section.query.filter_by(course_id=course_id).order_by(Section.order).all()

    return render_template('admin/course_content.html',
                           active_page='courses',
                           course=course,
                           sections=sections)


@app.route('/admin/add_section/<int:course_id>', methods=['POST'])
@admin_required
def admin_add_section(course_id):
    title = request.form.get('title')
    content = request.form.get('content')
    video_url = request.form.get('video_url')
    duration = request.form.get('duration', type=int)
    has_quiz = 'has_quiz' in request.form

    # 获取当前最大的order值
    max_order = db.session.query(db.func.max(Section.order)).filter_by(course_id=course_id).scalar() or 0

    # 创建新章节
    new_section = Section(
        course_id=course_id,
        title=title,
        content=content,
        video_url=video_url,
        duration=duration,
        has_quiz=has_quiz,
        order=max_order + 1
    )
    db.session.add(new_section)
    db.session.commit()

    flash('章节添加成功！', 'success')
    return redirect(url_for('admin_course_content', course_id=course_id))


@app.route('/admin/edit_section/<int:section_id>', methods=['POST'])
@admin_required
def admin_edit_section(section_id):
    title = request.form.get('title')
    content = request.form.get('content')
    video_url = request.form.get('video_url')
    duration = request.form.get('duration', type=int)
    has_quiz = 'has_quiz' in request.form

    section = db.session.get(Section, section_id)
    if not section:
        flash('章节不存在。', 'danger')
        return redirect(url_for('admin_courses'))

    # 更新章节信息
    section.title = title
    section.content = content
    section.video_url = video_url
    section.duration = duration
    section.has_quiz = has_quiz
    section.updated_at = datetime.now()

    db.session.commit()

    flash('章节信息更新成功！', 'success')
    return redirect(url_for('admin_course_content', course_id=section.course_id))


@app.route('/admin/delete_section/<int:section_id>', methods=['POST'])
@admin_required
def admin_delete_section(section_id):
    section = db.session.get(Section, section_id)
    if not section:
        flash('章节不存在。', 'danger')
        return redirect(url_for('admin_courses'))
    course_id = section.course_id

    db.session.delete(section)
    db.session.commit()

    # 重新排序剩余章节
    remaining_sections = Section.query.filter_by(course_id=course_id).order_by(Section.order).all()
    for i, section in enumerate(remaining_sections, 1):
        section.order = i
    db.session.commit()

    flash('章节删除成功！', 'success')
    return redirect(url_for('admin_course_content', course_id=course_id))


@app.route('/admin/enrollments')
@admin_required
def admin_enrollments():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    enrollments = Enrollment.query.paginate(page=page, per_page=per_page, error_out=False)

    pagination = {
        'page': enrollments.page,
        'pages': enrollments.pages,
        'total': enrollments.total,
        'has_prev': enrollments.has_prev,
        'has_next': enrollments.has_next
    }

    # 获取所有用户和课程，用于添加/编辑选课
    users = User.query.filter_by(is_admin=False).all()
    all_courses = Course.query.all()

    return render_template('admin/enrollments.html',
                           active_page='enrollments',
                           enrollments=enrollments.items,
                           pagination=pagination,
                           users=users,
                           all_courses=all_courses)

def 短信通知_课程开通(phone_number, name, course_name):
    ems.send_sms(15521397691, "猪猪侠", "人工智能训练师-数据智能应用")

@app.route('/admin/add_enrollment', methods=['POST'])
@admin_required
def admin_add_enrollment():
    with app.app_context():
        user_id = request.form.get('user_id')
        course_id = request.form.get('course_id')

        # 检查是否已存在该选课记录
        existing_enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
        if existing_enrollment:
            flash('该学员已注册此课程。', 'warning')
            return redirect(url_for('admin_enrollments'))

        # 创建新选课记录
        new_enrollment = Enrollment(user_id=user_id, course_id=course_id)
        db.session.add(new_enrollment)
        db.session.commit()
        # 从数据库获取该学员报名的课程名称、手机号、用户名（从数据库中读取内容）
        course_name = Course.query.get(course_id).title
        phone_number = User.query.get(user_id).phone
        name = User.query.get(user_id).username
        ems.send_sms(phone_number, name, course_name)
        flash('选课记录添加成功！', 'success')
        return redirect(url_for('admin_enrollments'))


@app.route('/admin/edit_enrollment', methods=['POST'])
@admin_required
def admin_edit_enrollment():
    enrollment_id = request.form.get('enrollment_id')
    user_id = request.form.get('user_id')
    course_id = request.form.get('course_id')
    progress = request.form.get('progress', type=int)
    is_completed = 'is_completed' in request.form

    enrollment = db.session.get(Enrollment, enrollment_id)
    if not enrollment:
        flash('选课记录不存在。', 'danger')
        return redirect(url_for('admin_enrollments'))

    # 检查是否与其他选课记录冲突
    if enrollment.user_id != int(user_id) or enrollment.course_id != int(course_id):
        existing_enrollment = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
        if existing_enrollment:
            flash('该学员已注册此课程。', 'warning')
            return redirect(url_for('admin_enrollments'))

    # 更新选课记录
    enrollment.user_id = user_id
    enrollment.course_id = course_id
    enrollment.progress = progress
    enrollment.is_completed = is_completed

    db.session.commit()

    flash('选课记录更新成功！', 'success')
    return redirect(url_for('admin_enrollments'))


@app.route('/admin/delete_enrollment', methods=['POST'])
@admin_required
def admin_delete_enrollment():
    enrollment_id = request.form.get('enrollment_id')

    enrollment = db.session.get(Enrollment, enrollment_id)
    if not enrollment:
        flash('选课记录不存在。', 'danger')
        return redirect(url_for('admin_enrollments'))
    db.session.delete(enrollment)
    db.session.commit()

    flash('选课记录删除成功！', 'success')
    return redirect(url_for('admin_enrollments'))


# 订单管理路由
@app.route('/admin/orders')
@admin_required
def admin_orders():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 获取筛选参数
    status = request.args.get('status')
    user_id = request.args.get('user_id', type=int)
    course_id = request.args.get('course_id', type=int)

    # 构建查询
    query = Order.query

    if status:
        query = query.filter(Order.status == status)
    if user_id:
        query = query.filter(Order.user_id == user_id)
    if course_id:
        query = query.filter(Order.course_id == course_id)

    # 获取分页订单
    orders = query.order_by(Order.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    pagination = {
        'page': orders.page,
        'pages': orders.pages,
        'total': orders.total,
        'has_prev': orders.has_prev,
        'has_next': orders.has_next
    }

    # 获取所有用户和课程，用于筛选
    users = User.query.all()
    all_courses = Course.query.all()

    return render_template('admin/orders.html',
                           active_page='orders',
                           orders=orders.items,
                           pagination=pagination,
                           users=users,
                           courses=all_courses,
                           status_options=['pending', 'completed', 'failed', 'refunded'])


@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    order = db.session.get(Order, order_id)
    if not order:
        flash('订单不存在', 'danger')
        return redirect(url_for('admin_orders'))

    user = db.session.get(User, order.user_id)
    course = db.session.get(Course, order.course_id)

    return render_template('admin/order_detail.html',
                           active_page='orders',
                           order=order,
                           user=user,
                           course=course)


@app.route('/admin/order/refund/<int:order_id>', methods=['POST'])
@admin_required
def admin_order_refund(order_id): #真实退款接口
    # 由公司财务处理退款，中断操作。
    flash('仅做登记处理，实际退款通道权限已被关闭，请提交至财务处理退款。', 'warning')
    return redirect(url_for('admin_order_detail', order_id=order_id))

    order = db.session.get(Order, order_id)
    if not order:
        flash('订单不存在', 'danger')
        return redirect(url_for('admin_orders'))

    if order.status != 'completed':
        flash('只有已完成的订单才能退款', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    # 处理退款
    refund_amount = request.form.get('refund_amount')
    refund_amount = float(refund_amount)
    print(request.form)
    print(refund_amount)
    if not refund_amount:
        flash('请输入退款金额', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    if refund_amount <= 0 or refund_amount > order.amount:
        flash('退款金额无效', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    # 调用富友退款接口
    refund_result = refund_fuiou_payment(order, refund_amount)

    if refund_result:
        # 更新订单状态
        order.status = 'refunded'
        order.refund_status = 'completed'
        order.refund_amount += refund_amount
        order.refund_time = datetime.now()

        # 如果全额退款，移除用户的课程
        if refund_amount == order.amount/100:
            enrollment = Enrollment.query.filter_by(user_id=order.user_id, course_id=order.course_id).first()
            if enrollment:
                db.session.delete(enrollment)

        db.session.commit()
        flash('退款成功', 'success')
    else:
        flash('退款失败，请稍后重试', 'danger')

    return redirect(url_for('admin_order_detail', order_id=order_id))

@app.route('/admin/order/refund2/<int:order_id>', methods=['POST'])
@admin_required
def admin_order_refund2(order_id): #真实退款接口
    # 由公司财务处理退款，中断操作。
    # flash('仅做登记处理2，实际退款通道权限已被关闭，请提交至财务处理退款。', 'warning')
    # return redirect(url_for('admin_order_detail', order_id=order_id))

    order = db.session.get(Order, order_id)
    if not order:
        flash('订单不存在', 'danger')
        return redirect(url_for('admin_orders'))

    if order.status != 'completed':
        flash('只有已完成的订单才能平账', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    # 处理退款
    refund_amount = request.form.get('refund_amount2')
    refund_amount = float(refund_amount)
    print(request.form)
    print(refund_amount)
    if not refund_amount:
        flash('请输入平账金额', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    if refund_amount <= 0 or refund_amount > order.amount:
        flash('平账金额无效', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    # 模拟退款成功
    refund_result = True

    if refund_result:
        # 更新订单状态
        order.status = 'refunded'
        order.refund_status = 'completed'
        order.refund_amount += refund_amount
        order.refund_time = datetime.now()

        # 如果全额退款，移除用户的课程
        if refund_amount >= order.amount/100:
            enrollment = Enrollment.query.filter_by(user_id=order.user_id, course_id=order.course_id).first()
            if enrollment:
                db.session.delete(enrollment)

        db.session.commit()
        flash('退款成功', 'success')
    else:
        flash('退款失败，请稍后重试', 'danger')

    return redirect(url_for('admin_order_detail', order_id=order_id))

def refund_fuiou_payment(order, refund_amount):
    """调用富友退款接口"""
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    current_time = datetime.now().strftime('%Y%m%d%H%M%S')

    # 退款金额必须是以分为单位的整数
    refund_amt = int(float(refund_amount) * 100)
    total_amt = order.amount  # 订单原始支付金额，单位是分
    term_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # 终端号

    params = {
        'version': '1.0', #版本号
        'mchnt_cd': FUIOU_CONFIG['mchnt_cd'], #商户号
        'term_id': term_id, #终端号，备用字段，传任意 8 字节字符即可
        'random_str': random_str, #随机字符串
        'mchnt_order_no': order.order_no, #商户系统内部的订单号
        # **商户退款订单号**，商户系统内部的退款订单号，必须保证唯一性
        'refund_order_no': f"{FUIOU_CONFIG['order_prefix']}{int(time.time())}{random.randint(1000, 9999)}",
        # 订单类型：
        # ALIPAY(统一下单、条码支付、服务窗支付)# WECHAT(统一下单、条码支付，公众号支付)
        # UNIONPAY# WXAPP(微信app)# ALIAPP(支付宝app)# WXH5(微信h5)# ALIH5(支付宝h5)# WXBX(微信保险类)# ALBX(支付宝保险类)# WXXS(微信线上所有交易)
        'order_type': order.payment_method,  # **支付方式**
        'total_amt': str(total_amt), #订单金额,分为单位的整数
        'refund_amt': str(refund_amt),#退款金额以分为单位
        # 'txn_begin_ts': current_time,#
    }

    # **按照文档的顺序生成签名**
    sign_str = (
        f"{params['mchnt_cd']}|{params['order_type']}|{params['mchnt_order_no']}|"
        f"{params['refund_order_no']}|{params['total_amt']}|{params['refund_amt']}|"
        f"{params['term_id']}|{params['random_str']}|{params['version']}|{FUIOU_CONFIG['mchnt_key']}"
    )
    params['sign'] = hashlib.md5(sign_str.encode()).hexdigest()

    try:
        print("🔹 发送退款请求到:", FUIOU_CONFIG['refund_url'])
        print("🔹 请求参数:", json.dumps(params, indent=4, ensure_ascii=False))

        response = requests.post(FUIOU_CONFIG['refund_url'], json=params, timeout=10)

        print("🔹 富友退款响应:", response.status_code, response.text)

        result = response.json()

        if result.get('result_code') == '000000':
            print("✅ 退款成功!")
            return True
        else:
            print(f"❌ 退款失败: {result.get('result_msg', '未知错误')}")
            return False
    except requests.exceptions.Timeout:
        print("❌ 退款请求超时")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ 退款请求异常: {str(e)}")
        return False
    except json.JSONDecodeError:
        print(f"❌ 退款返回的不是 JSON: {response.text}")
        return False


@app.route('/admin/settings')
@admin_required
def admin_settings():
    return render_template('admin/settings.html', active_page='settings')


@app.route('/admin/content')
@admin_required
def admin_content():
    courses = Course.query.all()
    return render_template('admin/content.html', active_page='content', courses=courses)


@app.route('/admin/logout')
def admin_logout():
    session.pop('user_id', None)
    flash('您已成功退出管理后台。', 'info')
    return redirect(url_for('admin_login'))


# 添加图片上传路由
@app.route('/admin/api/upload_image', methods=['POST'])
@admin_required
def upload_image():
    try:
        print("接收到图片上传请求")
        if 'image' not in request.files:
            print("请求中没有图片文件")
            return jsonify({'success': False, 'message': '没有上传文件'})

        file = request.files['image']
        if file.filename == '':
            print("文件名为空")
            return jsonify({'success': False, 'message': '没有选择文件'})

        if file:
            # 确保目录存在
            upload_dir = os.path.join('static', 'images', 'ke')
            os.makedirs(upload_dir, exist_ok=True)
            print(f"上传目录: {upload_dir}")

            # 生成安全的文件名
            from werkzeug.utils import secure_filename
            import uuid
            filename = secure_filename(file.filename)
            # 添加UUID前缀避免文件名冲突
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(upload_dir, unique_filename)
            print(f"保存文件到: {file_path}")

            # 保存文件
            file.save(file_path)

            # 返回文件URL
            image_url = f'/{file_path.replace(os.path.sep, "/")}'
            print(f"图片URL: {image_url}")
            return jsonify({'success': True, 'image_url': image_url})

        return jsonify({'success': False, 'message': '上传失败'})
    except Exception as e:
        import traceback
        print(f"图片上传错误: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})




# 添加课程API
@app.route('/admin/api/courses/add', methods=['POST'])
@admin_required
def add_course_api():
    try:
        print("接收到添加课程请求")
        data = request.get_json()
        if not data:
            print("无效的请求数据")
            return jsonify({'success': False, 'message': '无效的请求数据'})

        print(f"课程数据: {data}")

        # 创建新课程
        new_course = Course(
            title=data.get('title', ''),
            description=data.get('description', ''),
            instructor=data.get('instructor', ''),
            image=data.get('image', ''),
            is_published=data.get('is_published', False)
        )
        db.session.add(new_course)
        db.session.commit()

        print(f"新课程已创建: ID={new_course.id}, 标题={new_course.title}")
        return jsonify({'success': True, 'course_id': new_course.id})
    except Exception as e:
        db.session.rollback()
        import traceback
        print(f"添加课程时出错: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})


# 更新课程内容API
@app.route('/admin/api/courses/<int:course_id>/update', methods=['POST'])
@admin_required
def update_course_content(course_id):
    try:
        print(f"接收到课程 {course_id} 的更新请求")
        data = request.get_json()
        if not data:
            print("无效的请求数据")
            return jsonify({'success': False, 'message': '无效的请求数据'})

        print(f"课程数据: {data}")

        # 获取课程
        course = db.session.get(Course, course_id)
        if not course:
            print(f"课程 {course_id} 不存在")
            return jsonify({'success': False, 'message': '课程不存在'})

        # 更新课程基本信息
        course.title = data.get('title')
        course.description = data.get('description')
        course.instructor = data.get('instructor')
        course.image = data.get('image')
        course.is_published = data.get('is_published')
        course.updated_at = datetime.now()
        print(f"更新课程基本信息: {course.title}")

        # 处理章节
        existing_section_ids = [section.id for section in course.sections]
        updated_section_ids = []
        new_sections_data = []  # 存储新章节的ID信息

        for section_data in data.get('sections', []):
            section_id = section_data.get('id')
            print(f"处理章节: {section_id}")

            # 如果是新章节
            if section_id == 'new':
                section = Section(
                    course_id=course.id,
                    title=section_data.get('title'),
                    content=section_data.get('content', ''),
                    video_url=section_data.get('video_url', ''),
                    duration=section_data.get('duration', 0),
                    order=section_data.get('order', 0)
                )
                db.session.add(section)
                db.session.flush()  # 获取新章节ID
                updated_section_ids.append(section.id)
                print(f"添加新章节: {section.id}")

                # 处理新章节的课时
                lessons_data = []
                for lesson_data in section_data.get('lessons', []):
                    lesson = Lesson(
                        section_id=section.id,
                        title=lesson_data.get('title'),
                        order=lesson_data.get('order', 0)
                    )
                    db.session.add(lesson)
                    db.session.flush()  # 获取新课时ID
                    lessons_data.append({
                        'id': lesson.id,
                        'title': lesson.title,
                        'order': lesson.order
                    })

                # 添加到新章节数据中
                new_sections_data.append({
                    'id': section.id,
                    'title': section.title,
                    'lessons': lessons_data
                })
            else:
                # 更新现有章节
                try:
                    section_id = int(section_id)
                    section = db.session.get(Section, section_id)
                    if section and section.course_id == course.id:
                        section.title = section_data.get('title')
                        # section.content = section_data.get('content', ''),
                        # section.video_url = section_data.get('video_url', ''),

                        section.content = section_data.get('content', '')
                        section.video_url = section_data.get('video_url', '')

                        section.duration = section_data.get('duration', 0)
                        section.order = section_data.get('order', 0)
                        section.updated_at = datetime.now()
                        updated_section_ids.append(section.id)
                        print(f"更新章节: {section.id}")

                        # 处理章节的课时
                        existing_lesson_ids = [lesson.id for lesson in section.lessons] if hasattr(section,
                                                                                                   'lessons') else []
                        updated_lesson_ids = []

                        for lesson_data in section_data.get('lessons', []):
                            lesson_id = lesson_data.get('id')

                            # 如果是新课时
                            if lesson_id == 'new':
                                lesson = Lesson(
                                    section_id=section.id,
                                    title=lesson_data.get('title'),
                                    order=lesson_data.get('order', 0)
                                )
                                db.session.add(lesson)
                                db.session.flush()  # 获取新课时ID
                                updated_lesson_ids.append(lesson.id)
                            else:
                                # 更新现有课时
                                try:
                                    lesson_id = int(lesson_id)
                                    lesson = db.session.get(Lesson, lesson_id)
                                    if lesson and lesson.section_id == section.id:
                                        lesson.title = lesson_data.get('title')
                                        lesson.order = lesson_data.get('order', 0)
                                        updated_lesson_ids.append(lesson.id)
                                except (ValueError, TypeError) as e:
                                    print(f"处理课时ID {lesson_id} 时出错: {e}")
                                    continue

                        # 删除不在更新列表中的课时
                        for lesson_id in existing_lesson_ids:
                            if lesson_id not in updated_lesson_ids:
                                lesson = db.session.get(Lesson, lesson_id)
                                if lesson:
                                    print(f"删除课时: {lesson.id}")
                                    db.session.delete(lesson)
                except (ValueError, TypeError) as e:
                    print(f"处理章节ID {section_id} 时出错: {e}")
                    continue

        # 删除不在更新列表中的章节
        for section_id in existing_section_ids:
            if section_id not in updated_section_ids:
                section = db.session.get(Section, section_id)
                if section:
                    print(f"删除章节: {section.id}")
                    db.session.delete(section)

        db.session.commit()
        print("课程内容更新成功")
        return jsonify({'success': True, 'sections': new_sections_data})
    except Exception as e:
        db.session.rollback()
        import traceback
        print(f"更新课程内容时出错: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/comments')
@admin_required
def admin_comments():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Get filter parameters
    user_id = request.args.get('user_id', type=int)
    course_id = request.args.get('course_id', type=int)
    visibility = request.args.get('visibility')
    keyword = request.args.get('keyword')

    # Build query
    query = Comment.query

    if user_id:
        query = query.filter(Comment.user_id == user_id)

    if course_id:
        query = query.filter(Comment.course_id == course_id)

    if visibility:
        query = query.filter(Comment.visibility == visibility)

    if keyword:
        query = query.filter(Comment.content.like(f'%{keyword}%'))

    # 获取分页评论
    comments = query.order_by(Comment.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # 获取所有用户和课程以供筛选下拉菜单使用
    users = User.query.all()
    courses = Course.query.all()

    pagination = {
        'page': comments.page,
        'pages': comments.pages,
        'total': comments.total,
        'has_prev': comments.has_prev,
        'has_next': comments.has_next
    }

    # 计算分页范围，在模板中使用max/min
    start_page = max(1, pagination['page'] - 2)
    end_page = min(pagination['pages'] + 1, pagination['page'] + 3)
    page_range = list(range(start_page, end_page))

    return render_template('admin/comments.html',
                           active_page='comments',
                           comments=comments.items,
                           pagination=pagination,
                           page_range=page_range,
                           users=users,
                           courses=courses,
                           request=request)


@app.route('/admin/delete_comment', methods=['POST'])
@admin_required
def admin_delete_comment():
    data = request.get_json()
    comment_id = data.get('comment_id')

    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({'success': False, 'message': '评论不存在'})

    try:
        db.session.delete(comment)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/update_comment_visibility', methods=['POST'])
@admin_required
def admin_update_comment_visibility():
    data = request.get_json()
    comment_id = data.get('comment_id')
    visibility = data.get('visibility')

    if not visibility in ['public', 'admin_self', 'self']:
        return jsonify({'success': False, 'message': '无效的可见性设置'})

    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({'success': False, 'message': '评论不存在'})

    try:
        comment.visibility = visibility
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/batch_delete_comments', methods=['POST'])
@admin_required
def admin_batch_delete_comments():
    data = request.get_json()
    comment_ids = data.get('comment_ids', [])

    if not comment_ids:
        return jsonify({'success': False, 'message': '未选择任何评论'})

    try:
        Comment.query.filter(Comment.id.in_(comment_ids)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/batch_update_comment_visibility', methods=['POST'])
@admin_required
def admin_batch_update_comment_visibility():
    data = request.get_json()
    comment_ids = data.get('comment_ids', [])
    visibility = data.get('visibility')

    if not comment_ids:
        return jsonify({'success': False, 'message': '未选择任何评论'})

    if not visibility in ['public', 'admin_self', 'self']:
        return jsonify({'success': False, 'message': '无效的可见性设置'})

    try:
        Comment.query.filter(Comment.id.in_(comment_ids)).update({Comment.visibility: visibility},
                                                                 synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/get_comment_replies')
@admin_required
def admin_get_comment_replies():
    comment_id = request.args.get('comment_id', type=int)
    comment = Comment.query.get_or_404(comment_id)
    replies = Reply.query.filter_by(comment_id=comment_id).all()

    return jsonify({
        'success': True,
        'comment': {
            'username': comment.user.username,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M'),
            'content': comment.content,
            'user_avatar': comment.user.avatar  # 确保返回用户头像
        },
        'replies': [{
            'id': reply.id,
            'username': reply.user.username,
            'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
            'content': reply.content,
            'user_avatar': reply.user.avatar
        } for reply in replies]
    })


@app.route('/admin/delete_reply', methods=['POST'])
@admin_required
def admin_delete_reply():
    data = request.get_json()
    reply_id = data.get('reply_id')

    reply = Reply.query.get(reply_id)
    if not reply:
        return jsonify({'success': False, 'message': '回复不存在'})

    try:
        db.session.delete(reply)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


# 管理员回复评论的路由

@app.route('/admin/add_reply', methods=['POST'])
@admin_required
def admin_add_reply():
    data = request.get_json()
    comment_id = data.get('comment_id')
    content = data.get('content')

    if not content or not comment_id:
        return jsonify({'success': False, 'message': '参数不完整'})

    # 检查评论是否存在
    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({'success': False, 'message': '评论不存在'})

    # 获取当前管理员用户
    user_id = session['user_id']
    user = User.query.get(user_id)

    # 创建新的回复
    try:
        reply = Reply(
            comment_id=comment_id,
            user_id=user_id,
            content=content
        )
        db.session.add(reply)
        db.session.commit()

        # 返回回复数据
        return jsonify({
            'success': True,
            'reply': {
                'id': reply.id,
                'content': reply.content,
                'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
                'username': user.username,
                'user_avatar': user.avatar
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


# 用户兑换页面
@app.route('/redeem')
@login_required
def redeem():
    user = db.session.get(User, session['user_id'])

    # 获取用户的兑换记录
    redemption_records = RedemptionRecord.query.filter_by(user_id=user.id).order_by(
        RedemptionRecord.redeemed_at.desc()).all()

    # 获取头像URL
    avatar_url = url_for('static', filename=f'images/avatar_imgs/{user.avatar}')

    return render_template('redeem.html', user=user, redemption_records=redemption_records, avatar_url=avatar_url)


# 处理兑换码提交
@app.route('/redeem_code', methods=['POST'])
@login_required
def redeem_code():
    code = request.form.get('code')
    user_id = session['user_id']

    if not code:
        flash('请输入兑换码', 'danger')
        return redirect(url_for('redeem'))

    # 查找兑换码
    redemption_code = RedemptionCode.query.filter_by(code=code, is_used=False).first()

    if not redemption_code:
        flash('无效的兑换码或兑换码已被使用', 'danger')
        return redirect(url_for('redeem'))

    # 检查用户是否已经注册了该课程
    existing_enrollment = Enrollment.query.filter_by(
        user_id=user_id,
        course_id=redemption_code.course_id
    ).first()

    if existing_enrollment:
        flash('您已经注册了这门课程', 'info')
        return redirect(url_for('dashboard'))

    # 标记兑换码为已使用
    redemption_code.is_used = True
    redemption_code.used_at = datetime.now()
    redemption_code.used_by = user_id

    # 创建选课记录
    new_enrollment = Enrollment(user_id=user_id, course_id=redemption_code.course_id)
    db.session.add(new_enrollment)

    # 创建兑换记录
    ip_address = request.remote_addr
    redemption_record = RedemptionRecord(
        user_id=user_id,
        course_id=redemption_code.course_id,
        code_id=redemption_code.id,
        ip_address=ip_address
    )
    db.session.add(redemption_record)

    db.session.commit()

    flash('课程兑换成功！', 'success')
    return redirect(url_for('dashboard'))


# 管理员兑换码管理页面
@app.route('/admin/redemption_codes')
@admin_required
def admin_redemption_codes():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    codes = RedemptionCode.query.order_by(RedemptionCode.created_at.desc()).paginate(page=page, per_page=per_page,
                                                                                     error_out=False)

    pagination = {
        'page': codes.page,
        'pages': codes.pages,
        'total': codes.total,
        'has_prev': codes.has_prev,
        'has_next': codes.has_next
    }

    # 获取所有课程，用于生成新的兑换码
    courses = Course.query.filter_by(is_published=True).all()

    return render_template('admin/redemption_codes.html',
                           active_page='redemption_codes',
                           codes=codes.items,
                           pagination=pagination,
                           courses=courses)


# 生成兑换码
@app.route('/admin/generate_redemption_code', methods=['POST'])
@admin_required
def admin_generate_redemption_code():
    course_id = request.form.get('course_id')
    count = request.form.get('count', type=int, default=1)

    if not course_id:
        flash('请选择课程', 'danger')
        return redirect(url_for('admin_redemption_codes'))

    if count < 1 or count > 100:
        flash('生成数量必须在1-100之间', 'danger')
        return redirect(url_for('admin_redemption_codes'))

    # 生成指定数量的兑换码
    import random
    import string

    codes = []
    for _ in range(count):
        # 生成随机兑换码
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        # 创建兑换码记录
        redemption_code = RedemptionCode(
            code=code,
            course_id=course_id,
            created_by=session['user_id']
        )
        db.session.add(redemption_code)
        codes.append(code)

    db.session.commit()

    if count == 1:
        flash(f'兑换码生成成功: {codes[0]}', 'success')
    else:
        flash(f'成功生成 {count} 个兑换码', 'success')

    return redirect(url_for('admin_redemption_codes'))


# 删除兑换码
@app.route('/admin/delete_redemption_code', methods=['POST'])
@admin_required
def admin_delete_redemption_code():
    code_id = request.form.get('code_id')

    code = db.session.get(RedemptionCode, code_id)
    if not code:
        flash('兑换码不存在', 'danger')
        return redirect(url_for('admin_redemption_codes'))

    # 只能删除未使用的兑换码
    if code.is_used:
        flash('无法删除已使用的兑换码', 'danger')
        return redirect(url_for('admin_redemption_codes'))

    db.session.delete(code)
    db.session.commit()

    flash('兑换码删除成功', 'success')
    return redirect(url_for('admin_redemption_codes'))


@app.route('/redeem/<code>')
def redeem_code_direct(code):
    # 查找兑换码
    redemption_code = RedemptionCode.query.filter_by(code=code, is_used=False).first()

    if not redemption_code:
        flash('无效的兑换码或兑换码已被使用', 'danger')
        return redirect(url_for('login'))

    # 获取课程信息
    course = Course.query.get(redemption_code.course_id)
    if not course:
        flash('课程不存在', 'danger')
        return redirect(url_for('login'))

    # 如果用户已登录，检查是否已拥有该课程
    if 'user_id' in session:
        existing_enrollment = Enrollment.query.filter_by(
            user_id=session['user_id'],
            course_id=course.id
        ).first()

        if existing_enrollment:
            flash('您已经注册了这门课程', 'info')
            return redirect(url_for('dashboard'))

        # 标记兑换码为已使用状态，并记录使用时间和使用者的用户ID
        redemption_code.is_used = True
        redemption_code.used_at = datetime.now()
        redemption_code.used_by = session['user_id']

        # 创建一个新的课程注册记录
        new_enrollment = Enrollment(user_id=session['user_id'], course_id=course.id)
        db.session.add(new_enrollment)

        # 记录用户兑换课程的详细信息，包括用户ID、课程ID、兑换码ID以及用户的IP地址。
        redemption_record = RedemptionRecord(
            user_id=session['user_id'],
            course_id=course.id,
            code_id=redemption_code.id,
            ip_address=request.remote_addr
        )
        db.session.add(redemption_record)

        db.session.commit()

        flash('课程兑换成功！', 'success')
        return redirect(url_for('dashboard'))

    # 如果用户未登录，函数将渲染一个用于输入兑换码的表单页面。
    return render_template('redeem_code.html', code=code, course=course)


@app.route('/redeem/<code>/activate', methods=['POST'])
def redeem_code_activate(code):
    username = request.form.get('username')
    phone = request.form.get('phone')

    if not username or not phone:
        flash('请填写所有必填字段', 'danger')
        return redirect(url_for('redeem_code_direct', code=code))

    # 查找兑换码未被使用
    redemption_code = RedemptionCode.query.filter_by(code=code, is_used=False).first()

    if not redemption_code:
        flash('无效的兑换码或兑换码已被使用', 'danger')
        return redirect(url_for('login'))

    # 这段代码的功能是检查数据库中是否已存在与输入手机号匹配的用户。
    user = User.query.filter_by(phone=phone).first()

    # 如果不存在，则创建新用户；
    if not user:
        # 创建新用户
        # 默认密码为手机号后6位
        password = phone[-6:]
        hashed_password = generate_password_hash(password)

        # 检查用户是否存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # 如果存在就加一个随机三位数的后缀
            import random
            import string
            random_suffix = ''.join(random.choices(string.digits, k=3))
            username = f"{username}{random_suffix}"

        user = User(
            username=username,
            phone=phone,
            password=hashed_password,
            created_at=datetime.now()
        )
        db.session.add(user)
        db.session.flush()  # 获取用户ID

    # 如果存在，则继续后续操作。
    # 将兑换码标记为已使用，并记录使用时间和使用者的ID。
    redemption_code.is_used = True
    redemption_code.used_at = datetime.now()
    redemption_code.used_by = user.id

    # 检查用户是否已经拥有该课程
    existing_enrollment = Enrollment.query.filter_by(
        user_id=user.id,
        course_id=redemption_code.course_id
    ).first()

    if not existing_enrollment:
        # 课程关联
        new_enrollment = Enrollment(user_id=user.id, course_id=redemption_code.course_id)
        db.session.add(new_enrollment)

        # 记录用户使用兑换码兑换课程的相关信息，包括用户ID、课程ID、兑换码ID以及用户IP地址
        redemption_record = RedemptionRecord(
            user_id=user.id,
            course_id=redemption_code.course_id,
            code_id=redemption_code.id,
            ip_address=request.remote_addr
        )
        db.session.add(redemption_record)

    db.session.commit()

    # 用户登录信息存储到会话中(保存登录状态)
    session['user_id'] = user.id
    session['is_admin'] = user.is_admin

    # 课程兑换成功，发送短信
    import ems
    course = Course.query.get(redemption_code.course_id)
    if course:
        try:
            ems.send_sms(phone, username, course.title)
        except Exception as e:
            print(f"SMS notification failed: {str(e)}")

    flash('课程兑换成功！您已自动登录。', 'success')
    return redirect(url_for('dashboard'))

# 导入文章蓝图
# from blueprints.article import article_bp

# 注册蓝图
# app.register_blueprint(article_bp)

import article
app.register_blueprint(article.article_bp)


import ems
app.register_blueprint(ems.ems_bp)


def create_tables():
    with app.app_context():
        db.create_all()

        # 只有当数据库为空时添加示例数据
        if not User.query.first():
            # 添加管理员用户
            admin = User(
                username='admin',
                email='admin@gzturing.com',
                phone='13800000000',  # 添加手机号
                password=generate_password_hash('Turing888'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.add(User(
                username='turing',
                email='turing@gzturing.com',
                phone='13900000000',  # 添加手机号
                password=generate_password_hash('turing'),
                is_admin=False
            ))

            # 添加示例课程
            courses = [
                Course(
                    title='人工智能训练师',
                    description='新技能！新职业！岗前必学！助力认证！深入   习AIGC生成式工具（文本生成、图像生成、工作流等），并结合AI技术进行高级数据分析（包括数据挖掘、预测建模等），以支持更智能的决策过程，从而快速掌握AI训练师岗位专业技能。',
                    image='/static/images/ke/rgzn.jpg',
                    is_published=True,
                    instructor='陈老师、朱老师',
                    price=0.01#2700.0  # 添加价格
                ),
                Course(
                    title='AI趣味编程',
                    description='零基础无压力:从  简单的基础入手，逐步进阶，轻松掌握编程思维。趣味性强:利用海龟库画图和制作小游戏，让编程变得生动有趣。',
                    image='/static/images/ke/d00.png',
                    is_published=True,
                    instructor='陈老师、朱老师',
                    price=0.01#2700.0  # 添加价格
                ),
                Course(
                    title='21小时学会Python基础语法',
                    description='绘制简单几何图形、带有决策路径的迷宫、动态变化星形图案、重复的宝藏图案、个性化创作项目、基于列表的不同图形、动态变化的舞步图案、简单的点击按钮界面、多功能界面设计、商品选购、点读机。',
                    image='/static/images/ke/d0.png',
                    is_published=True,
                    instructor='陈老师',
                    price=0.01#2000.0  # 添加价格
                ),
                Course(
                    title='AI链程',
                    description='本课程从零基础教授学生如何使用过程式编程方法来构建项目。学生将学习变量、循环、条件语句等基本语法,并通过实际案例,如编写简单的游戏或工具,来实践过程式编程技巧。',
                    image='/static/images/ke/d1.png',
                    is_published=True,
                    instructor='陈老师',
                    price=0.01#900.0  # 添加价格
                ),
                Course(
                    title='AI元构',
                    description='本课程面向有编程基础的学生，学生将过渡到面向对象的编程思维,学习类、对象、继承、多态等概念。通过面向对象的项目实践,学生能够构建更加模块化和可重用的代码。',
                    image='/static/images/ke/d2.png',
                    is_published=True,
                    instructor='陈老师',
                    price=0.01#900.0  # 添加价格
                ),
                Course(
                    title='AI矿程',
                    description='本课程着重于数据获取的技术,包括网络爬虫的编写和数据处理的基本技巧。我们将学习如何从互联网上高效地收集数据,并进行初步的清洗和格式化。',
                    image='/static/images/ke/d3.png',
                    is_published=True,
                    instructor='陈老师、朱老师',
                    price=0.01#900.0  # 添加价格
                ),
                Course(
                    title='AI数瞳',
                    description='在这个模块中,学生将学习如何使用数据分析工具和技术来提升对数据的洞察力。课程内容包括数据可视化、基本统计分析以及机器学习算法的初步应用。',
                    image='/static/images/ke/d4.png',
                    is_published=True,
                    instructor='朱老师',
                    price=0.01#900.0  # 添加价格
                ),
                Course(
                    title='AI实战编程',
                    description='本课程是由四个实战项目组成的，使用Python作为后端开发，结合AI完成前后端的全栈开发，并全面了解项目部署的各个环节，提升学员的实战能力和项目管理能力。',
                    image='/static/images/ke/d5.png',
                    is_published=True,
                    instructor='朱老师',
                    price=0.01#500.0  # 添加价格
                ),

                Course(
                    title='AI-5天训练营',
                    description='AI训练营课程主要围绕利用AI技术提升内容创作、职场效率等多方面能力，涵盖文本、图像、视频、音频创作及职场效能跃迁，通过实操案例帮助学员掌握相关工具和方法。',
                    image='/static/images/ke/训练营.jpg',
                    is_published=True,
                    instructor='陈老师',
                    price=0#900  # 添加价格
                )
            ]
            db.session.add_all(courses)
            db.session.commit()
            sections = []
            # 为每个课程添加章节

            for course in courses[:-1]:

                for i in range(1, 6):  # 每个课程5个章节
                    section = Section(
                        course_id=course.id,
                        title=f'{course.title} - 第{i}章',
                        content=f'这是{course.title}的第{i}章内容。包含了详细的讲解和示例代码。',
                        video_url='1335108353.vod-qcloud.com||1397757906766532092',  # 示例视频URL
                        duration=30,  # 30分钟
                        order=i,
                        has_quiz=(i % 2 == 0)  # 偶数章节有测验
                    )
                    sections.append(section)

            course = courses[-1]
            video_url = [
                "1335108353.vod-qcloud.com||1397757906766532092",
                "1335108353.vod-qcloud.com||1397757906777933699",
                "1335108353.vod-qcloud.com||1397757906770185034",
                "1335108353.vod-qcloud.com||1397757906771124075",
                "1335108353.vod-qcloud.com||1397757906773610615",
                "1335108353.vod-qcloud.com||1397757906774491655",
                "1335108353.vod-qcloud.com||1397757906775388770",
                "1335108353.vod-qcloud.com||1397757906767829083",
                "1335108353.vod-qcloud.com||1397757906773610524",
                "1335108353.vod-qcloud.com||1397757906777250561"
            ]
            for i in range(1, 10 + 1):
                section = Section(
                    course_id=course.id,
                    title=f'{course.title} - 第{i}章',
                    content=f'这是{course.title}的第{i}章内容。包含了详细的讲解和示例演示。',
                    video_url=video_url[i - 1],
                    # 示例视频URL
                    duration=30,  # 30分钟
                    order=i,
                    has_quiz=(i % 2 == 0)  # 偶数章节有测验
                )
                sections.append(section)

            db.session.add_all(sections)
            db.session.commit()

            # # 为有测验的章节添加测验题目
            # quiz_sections = Section.query.filter_by(has_quiz=True).all()
            # for section in quiz_sections:
            #     questions = []
            #     for i in range(1, 4):  # 每个测验3个问题
            #         question = QuizQuestion(
            #             section_id=section.id,
            #             text=f'问题{i}: 关于{section.title}的以下描述，哪一个是正确的？',
            #             options='["选项A", "选项B", "选项C", "选项D"]',  # JSON格式的选项
            #             correct_answer=0  # 第一个选项是正确答案
            #         )
            #         questions.append(question)
            #
            #     db.session.add_all(questions)
            # db.session.commit()



if __name__ == '__main__':
    # payment_notify("106617421504565035","38250317091030793292")
    with app.app_context():
        db.create_all()  # 在应用启动前创建表并添加示例数据
    create_tables()  # 在应用启动前创建表并添加示例数据
    # 添加课程()
    # 添加定时任务：每隔10秒检测一次订单状态
    scheduler = BackgroundScheduler()
    scheduler.start()
    scheduler.add_job(func=check_and_process_pending_orders, trigger='interval', seconds=10)
    app.run(host='0.0.0.0', debug=False, port=8456)

