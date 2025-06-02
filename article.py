from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, abort
from datetime import datetime
import json
import re
from models import db, User, Course, Enrollment, Article, ArticleCategory, ArticleTag, article_tags, login_required, admin_required

article_bp = Blueprint('article', __name__)

# 文章列表页面
@article_bp.route('/articles')
def articles():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    category_id = request.args.get('category', type=int)
    tag_id = request.args.get('tag', type=int)

    # 构建查询
    query = Article.query.filter_by(is_published=True)

    # 只显示公开文章或登录用户可见的文章
    if 'user_id' in session:
        query = query.filter(
            (Article.visibility == 'public') | 
            (Article.visibility == 'login_required') |
            ((Article.visibility == 'admin_only') & 
             (User.query.get(session['user_id']).is_admin == True))
        )
    else:
        query = query.filter_by(visibility='public')

    # 应用分类和标签过滤
    if category_id:
        query = query.filter_by(category_id=category_id)

    if tag_id:
        # 修复：使用子查询获取包含特定标签的文章ID
        article_ids = db.session.query(article_tags.c.article_id).filter(
            article_tags.c.tag_id == tag_id
        ).all()
        article_ids = [id[0] for id in article_ids]  # 提取ID列表
        if article_ids:
            query = query.filter(Article.id.in_(article_ids))
        else:
            # 如果没有找到文章，返回空列表
            return render_template('articles/list.html', 
                           articles=[],
                           pagination=None,
                           categories=ArticleCategory.query.all(),
                           tags=ArticleTag.query.all(),
                           current_category=category_id,
                           current_tag=tag_id)

    # 首先获取置顶文章
    pinned_articles = query.filter_by(is_pinned=True).order_by(Article.created_at.desc()).all()

    # 然后获取非置顶文章
    regular_query = query.filter_by(is_pinned=False).order_by(Article.created_at.desc())
    regular_pagination = regular_query.paginate(page=page, per_page=per_page, error_out=False)

    # 获取所有分类和标签
    categories = ArticleCategory.query.all()
    tags = ArticleTag.query.all()

    # 合并置顶和非置顶文章
    all_articles = pinned_articles + regular_pagination.items

    return render_template('articles/list.html', 
                           articles=all_articles,
                           pagination=regular_pagination,
                           categories=categories,
                           tags=tags,
                           current_category=category_id,
                           current_tag=tag_id)

# 文章详情页面
@article_bp.route('/article/<int:article_id>')
def article_detail(article_id):
    article = Article.query.get_or_404(article_id)

    # 检查文章是否发布
    if not article.is_published:
        if 'user_id' not in session or not User.query.get(session['user_id']).is_admin:
            abort(404)

    # 检查文章可见性
    if article.visibility == 'login_required' and 'user_id' not in session:
        flash('此文章需要登录后才能查看', 'warning')
        return redirect(url_for('login', next=request.path))

    if article.visibility == 'admin_only' and ('user_id' not in session or not User.query.get(session['user_id']).is_admin):
        abort(403)

    # 处理密码保护的文章
    if article.visibility == 'password_protected':
        if f'article_access_{article.id}' not in session:
            return redirect(url_for('article.article_password', article_id=article.id))

    # 增加浏览次数
    article.view_count += 1
    db.session.commit()

    # 获取相关课程信息
    course = None
    is_enrolled = False
    if article.course_id:
        course = Course.query.get(article.course_id)
        if 'user_id' in session:
            is_enrolled = Enrollment.query.filter_by(
                user_id=session['user_id'], 
                course_id=article.course_id
            ).first() is not None

    # 获取相关文章
    related_articles = []
    if article.tags:
        tag_ids = [tag.id for tag in article.tags]
        related_articles = Article.query.filter(
            Article.id != article.id,
            Article.is_published == True,
            Article.tags.any(ArticleTag.id.in_(tag_ids))
        ).order_by(Article.created_at.desc()).limit(3).all()

    # 获取热门文章
    hot_articles = Article.query.filter_by(is_published=True).order_by(Article.view_count.desc()).limit(5).all()

    return render_template('articles/detail.html', 
                           article=article, 
                           course=course,
                           is_enrolled=is_enrolled,
                           related_articles=related_articles,
                           hot_articles=hot_articles)

# 文章密码验证
@article_bp.route('/article/<int:article_id>/password', methods=['GET', 'POST'])
def article_password(article_id):
    article = Article.query.get_or_404(article_id)

    if request.method == 'POST':
        password = request.form.get('password')

        if password == article.password:
            session[f'article_access_{article.id}'] = True
            return redirect(url_for('article.article_detail', article_id=article.id))
        else:
            flash('密码错误', 'danger')

    return render_template('articles/password.html', article=article)

# 管理员文章列表
@article_bp.route('/admin/articles')
@admin_required
def admin_articles():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 获取筛选参数
    status = request.args.get('status')
    category_id = request.args.get('category', type=int)
    visibility = request.args.get('visibility')

    # 构建查询
    query = Article.query

    if status == 'published':
        query = query.filter_by(is_published=True)
    elif status == 'draft':
        query = query.filter_by(is_published=False)

    if category_id:
        query = query.filter_by(category_id=category_id)

    if visibility:
        query = query.filter_by(visibility=visibility)

    # 获取分页文章
    articles = query.order_by(Article.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # 获取所有分类
    categories = ArticleCategory.query.all()

    return render_template('admin/articles/list.html',
                           active_page='articles',
                           articles=articles.items,
                           pagination=articles,
                           categories=categories,
                           status_options=['published', 'draft'],
                           visibility_options=['public', 'login_required', 'password_protected', 'admin_only'],
                           current_status=status,
                           current_category=category_id,
                           current_visibility=visibility)

# 添加/编辑文章页面
@article_bp.route('/admin/article/edit/<int:article_id>', methods=['GET', 'POST'])
@article_bp.route('/admin/article/add', methods=['GET', 'POST'])
@admin_required
def admin_article_edit(article_id=None):
    # 获取文章或创建新文章
    if article_id:
        article = Article.query.get_or_404(article_id)
        title = "编辑文章"
    else:
        article = Article()
        article.author_id = session['user_id']
        title = "添加文章"

    # 获取所有分类和标签
    categories = ArticleCategory.query.all()
    all_tags = ArticleTag.query.all()

    # 获取所有课程
    courses = Course.query.filter_by(is_published=True).all()

    if request.method == 'POST':
        # 获取表单数据
        article.title = request.form.get('title')
        article.content = request.form.get('content')
        article.category_id = request.form.get('category_id', type=int)
        article.is_published = 'is_published' in request.form
        article.is_pinned = 'is_pinned' in request.form
        article.show_on_homepage = 'show_on_homepage' in request.form
        article.visibility = request.form.get('visibility')

        # 处理密码
        if article.visibility == 'password_protected':
            password = request.form.get('password')
            if password:
                article.password = password
        else:
            article.password = None

        # 处理课程绑定
        course_id = request.form.get('course_id')
        if course_id and course_id != '0':
            article.course_id = int(course_id)
        else:
            article.course_id = None

        # 处理标签
        selected_tags = request.form.getlist('tags')
        article.tags = []
        for tag_id in selected_tags:
            tag = ArticleTag.query.get(int(tag_id))
            if tag:
                article.tags.append(tag)

        # 处理摘要
        summary = request.form.get('summary')
        if summary:
            article.summary = summary
        else:
            # 自动生成摘要
            content_text = re.sub(r'<.*?>', '', article.content)
            article.summary = content_text[:200] + '...' if len(content_text) > 200 else content_text

        # 处理封面图
        cover_image = request.form.get('cover_image')
        if cover_image:
            article.cover_image = cover_image

        # 保存文章
        if not article_id:
            article.created_at = datetime.now()
        article.updated_at = datetime.now()

        db.session.add(article)
        db.session.commit()

        flash('文章保存成功！', 'success')
        return redirect(url_for('article.admin_articles'))

    return render_template('admin/articles/edit.html',
                           active_page='articles',
                           article=article,
                           categories=categories,
                           all_tags=all_tags,
                           courses=courses,
                           title=title)

# 删除文章
@article_bp.route('/admin/article/delete/<int:article_id>', methods=['POST'])
@admin_required
def admin_article_delete(article_id):
    article = Article.query.get_or_404(article_id)

    db.session.delete(article)
    db.session.commit()

    flash('文章已删除', 'success')
    return redirect(url_for('article.admin_articles'))

# 文章分类管理
@article_bp.route('/admin/article/categories', methods=['GET', 'POST'])
@admin_required
def admin_article_categories():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            name = request.form.get('name')
            if name:
                category = ArticleCategory(name=name)
                db.session.add(category)
                db.session.commit()
                flash('分类添加成功', 'success')

        elif action == 'edit':
            category_id = request.form.get('category_id', type=int)
            name = request.form.get('name')
            if category_id and name:
                category = ArticleCategory.query.get(category_id)
                if category:
                    category.name = name
                    db.session.commit()
                    flash('分类更新成功', 'success')

        elif action == 'delete':
            category_id = request.form.get('category_id', type=int)
            if category_id:
                category = ArticleCategory.query.get(category_id)
                if category:
                    # 检查是否有文章使用此分类
                    if Article.query.filter_by(category_id=category_id).first():
                        flash('无法删除已被文章使用的分类', 'danger')
                    else:
                        db.session.delete(category)
                        db.session.commit()
                        flash('分类删除成功', 'success')

    categories = ArticleCategory.query.all()
    return render_template('admin/articles/categories.html',
                           active_page='article_categories',
                           categories=categories)

# 文章标签管理
@article_bp.route('/admin/article/tags', methods=['GET', 'POST'])
@admin_required
def admin_article_tags():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            name = request.form.get('name')
            if name:
                tag = ArticleTag(name=name)
                db.session.add(tag)
                db.session.commit()
                flash('标签添加成功', 'success')

        elif action == 'edit':
            tag_id = request.form.get('tag_id', type=int)
            name = request.form.get('name')
            if tag_id and name:
                tag = ArticleTag.query.get(tag_id)
                if tag:
                    tag.name = name
                    db.session.commit()
                    flash('标签更新成功', 'success')

        elif action == 'delete':
            tag_id = request.form.get('tag_id', type=int)
            if tag_id:
                tag = ArticleTag.query.get(tag_id)
                if tag:
                    db.session.delete(tag)
                    db.session.commit()
                    flash('标签删除成功', 'success')

    tags = ArticleTag.query.all()
    return render_template('admin/articles/tags.html',
                           active_page='article_tags',
                           tags=tags)

# 上传图片API
@article_bp.route('/admin/api/upload_article_image', methods=['POST'])
@admin_required
def upload_article_image():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'message': '没有上传文件'})

        file = request.files['image']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'})

        if file:
            # 确保目录存在
            import os
            upload_dir = os.path.join('static', 'images', 'articles')
            os.makedirs(upload_dir, exist_ok=True)

            # 生成安全的文件名
            from werkzeug.utils import secure_filename
            import uuid
            filename = secure_filename(file.filename)
            # 添加UUID前缀避免文件名冲突
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(upload_dir, unique_filename)

            # 保存文件
            file.save(file_path)

            # 返回文件URL
            image_url = f'/{file_path.replace(os.path.sep, "/")}'
            return jsonify({'success': True, 'image_url': image_url})

        return jsonify({'success': False, 'message': '上传失败'})
    except Exception as e:
        import traceback
        print(f"图片上传错误: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})

