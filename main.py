from flask import Flask
from extensions import db
from blueprints.article import article_bp
# 导入其他蓝图...

def create_app():
    app = Flask(__name__)
    
    # 配置数据库
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///education.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 初始化扩展
    db.init_app(app)
    
    # 注册蓝图
    app.register_blueprint(article_bp)
    # 注册其他蓝图...
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

