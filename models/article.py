from datetime import datetime
from extensions import db

# 文章与标签的多对多关系表
article_tags = db.Table('article_tags',
    db.Column('article_id', db.Integer, db.ForeignKey('article.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('article_tag.id'), primary_key=True)
)

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
    author = db.relationship('User', backref='articles')
    category = db.relationship('ArticleCategory', backref='articles')
    course = db.relationship('Course', backref='articles')
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

