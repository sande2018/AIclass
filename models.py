# models.py - 共享模型文件
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash

# 创建 SQLAlchemy 实例，但不立即初始化
db = SQLAlchemy()

# 文章与标签的多对多关系表
article_tags = db.Table('article_tags',
    db.Column('article_id', db.Integer, db.ForeignKey('article.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('article_tag.id'), primary_key=True)
)

# 定义数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # 改为可为空
    phone = db.Column(db.String(20), unique=True, nullable=True)  # 添加手机号字段
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)
    avatar = db.Column(db.String(100), default='avatar_0.svg')  # Add this line
    enrollments = db.relationship('Enrollment', backref='student', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='user', lazy=True, cascade="all, delete-orphan")
    replies = db.relationship('Reply', backref='user')
    orders = db.relationship('Order', backref='user', lazy=True, cascade="all, delete-orphan")
    articles = db.relationship('Article', backref='author')

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    instructor = db.Column(db.String(100), nullable=True)
    price = db.Column(db.Float, default=0.0)  # 添加价格字段
    is_published = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    enrollments = db.relationship('Enrollment', backref='course', lazy=True, cascade="all, delete-orphan")
    sections = db.relationship('Section', backref='course', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='course', lazy=True, cascade="all, delete-orphan")
    orders = db.relationship('Order', backref='course', lazy=True, cascade="all, delete-orphan")
    articles = db.relationship('Article', backref='course')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    enrollment_date = db.Column(db.DateTime, default=datetime.now)
    progress = db.Column(db.Integer, default=0)  # 0-100 百分比
    is_completed = db.Column(db.Boolean, default=False)
    completed_sections = db.relationship('CompletedSection', backref='enrollment', lazy=True,
                                         cascade="all, delete-orphan")

class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    video_url = db.Column(db.String(200), nullable=True)
    duration = db.Column(db.Integer, default=0)  # 分钟
    order = db.Column(db.Integer, default=0)
    has_quiz = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    quiz_questions = db.relationship('QuizQuestion', backref='section', lazy=True, cascade="all, delete-orphan")
    completed_by = db.relationship('CompletedSection', backref='section', lazy=True, cascade="all, delete-orphan")
    lessons = db.relationship('Lesson', backref='section', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='section', lazy=True, cascade="all, delete-orphan")

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class CompletedSection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollment.id'), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.now)
    quiz_score = db.Column(db.Integer, nullable=True)  # 如果有测验，记录分数

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    options = db.Column(db.Text, nullable=False)  # 存储为JSON字符串
    correct_answer = db.Column(db.Integer, nullable=False)  # 正确选项的索引

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    visibility = db.Column(db.String(20), default='public')  # 'public', 'admin_self', 'self'
    created_at = db.Column(db.DateTime, default=datetime.now)
    replies = db.relationship('Reply', backref='comment', lazy=True, cascade="all, delete-orphan")

# 添加 Reply 模型用于评论回复
class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

# 兑换码模型
class RedemptionCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    used_at = db.Column(db.DateTime, nullable=True)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    course = db.relationship('Course', backref='redemption_codes')
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_codes')
    user = db.relationship('User', foreign_keys=[used_by], backref='used_codes')

# 兑换记录模型
class RedemptionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    code_id = db.Column(db.Integer, db.ForeignKey('redemption_code.id'), nullable=False)
    redeemed_at = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(50), nullable=True)
    user = db.relationship('User', backref='redemption_records')
    course = db.relationship('Course', backref='redemption_records')
    code = db.relationship('RedemptionCode', backref='redemption_record')

# 订单模型
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # 以分为单位
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, refunded
    payment_method = db.Column(db.String(20))  # 支付方式
    transaction_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    paid_at = db.Column(db.DateTime, nullable=True)
    refund_status = db.Column(db.String(20), nullable=True)  # pending, completed
    refund_amount = db.Column(db.Integer, default=0)
    refund_time = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    summary = db.Column(db.String(500))
    cover_image = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('article_category.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    is_published = db.Column(db.Boolean, default=False)
    is_pinned = db.Column(db.Boolean, default=False)
    show_on_homepage = db.Column(db.Boolean, default=True)
    visibility = db.Column(db.String(20), default='public')  # public, login_required, password_protected, admin_only
    password = db.Column(db.String(100))
    view_count = db.Column(db.Integer, default=0)
    
    # 关系
    category = db.relationship('ArticleCategory', backref='articles')
    tags = db.relationship('ArticleTag', secondary=article_tags, backref=db.backref('articles', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Article {self.title}>'

class ArticleCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    
    def __repr__(self):
        return f'<ArticleCategory {self.name}>'

class ArticleTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    
    def __repr__(self):
        return f'<ArticleTag {self.name}>'

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

