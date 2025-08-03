from flask import Flask,render_template,url_for,request,flash,redirect,session,jsonify,current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_migrate import Migrate
from sqlalchemy import func,desc
from datetime import datetime
from collections import Counter
from flask_mail import Mail, Message
import random
from dotenv import load_dotenv
import requests
import json
from werkzeug.utils import secure_filename
app = Flask(__name__)
app.config['SECRET_KEY'] = '0658145f863644a6143bdb370000274e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'n7033752@gmail.com'  # your email
app.config['MAIL_PASSWORD'] = 'tucq oonl xbyu riqx' 
mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# load_dotenv()
# app.config['API_KEY'] = os.getenv('API_KEY')
#models
votes_association = db.Table('votes_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('answer_id', db.Integer, db.ForeignKey('answer.id'), primary_key=True),
    db.Column('vote_type', db.String(10), nullable=False)  # 'upvote' or 'downvote'
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)#use
    first_name=db.Column(db.String(90),unique=False, nullable=False)
    last_name=db.Column(db.String(90),unique=False, nullable=False)
    full_name=db.Column(db.String(90),unique=True, nullable=True)#use
    username = db.Column(db.String(80), unique=True, nullable=False)#use
    email = db.Column(db.String(120), unique=True, nullable=False)#use
    c_id = db.Column(db.String(200), nullable=False)#use
    password = db.Column(db.String(200), nullable=False)#use
    role = db.Column(db.String(20), default='student',nullable=True)#use
    department = db.Column(db.String(50), nullable=True)#use
    year = db.Column(db.String(90), nullable=True)#use
    bio = db.Column(db.Text, nullable=True)#use
    interest= db.Column(db.String(200), nullable=True)
    skiils=db.Column(db.String(200), nullable=True)
    location=db.Column(db.String(200), nullable=True)
    questions = db.relationship('Question', backref='author', lazy=True, cascade="all, delete")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.relationship('Answer', backref='author', lazy=True, cascade="all, delete")
    image = db.Column(db.String(300), nullable=True)
    otp=db.Column(db.Integer)#use
    achievement=db.Column(db.String(200), nullable=True)
    course=db.Column(db.String(200), nullable=True)
    verify= db.Column(db.Boolean, default=False)
    voted_on = db.relationship(
        'Answer', 
        secondary=votes_association, 
        back_populates='voters',
        cascade="all, delete"
    )
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('answer.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='comments', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    department = db.Column(db.String(50), nullable=True)
    subject = db.Column(db.String(50), nullable=True)
    image = db.Column(db.String(200), nullable=True)
    answers = db.relationship('Answer', backref='question', lazy=True, cascade="all, delete")

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='answer', lazy=True,cascade="all, delete")
    voters = db.relationship(
        'User', 
        secondary=votes_association,
        back_populates='voted_on',
        cascade="all, delete"
    )
    @property
    def score(self):
        # This is not a column in the DB, but a calculated value
        total_upvotes = db.session.query(votes_association).filter_by(answer_id=self.id, vote_type='upvote').count()
        total_downvotes = db.session.query(votes_association).filter_by(answer_id=self.id, vote_type='downvote').count()
        return total_upvotes - total_downvotes

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    message = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=True)  # Optional URL to redirect
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_notifications',cascade="all, delete")
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_notifications',cascade="all, delete")
#moderation
load_dotenv()

def is_question_safe(question):
    url = f"https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key={os.getenv('api_key')}"

    data = {
        "comment": {"text": question},
        "languages": ["en", "hi"], 
        "requestedAttributes": {
            "TOXICITY": {},
            "INSULT": {},
            "PROFANITY": {},
            "THREAT": {}
        }
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code != 200:
        print("❌ Error:", response.json())
        return False

    scores = response.json()["attributeScores"]

    toxicity = scores["TOXICITY"]["summaryScore"]["value"]
    insult = scores["INSULT"]["summaryScore"]["value"]
    profanity = scores["PROFANITY"]["summaryScore"]["value"]
    threat = scores["THREAT"]["summaryScore"]["value"]
    if toxicity > 0.5 or insult > 0.7 or profanity > 0.6 or threat > 0.5:
        return False
    else:
        return True
    
@app.template_filter('time_ago')
def time_ago(date):
    now = datetime.utcnow()
    diff = now - date
    
    periods = [
        ('year', 60*60*24*365),
        ('month', 60*60*24*30),
        ('day', 60*60*24),
        ('hour', 60*60),
        ('minute', 60),
        ('second', 1)
    ]
    
    for period, seconds in periods:
        value = diff.total_seconds() / seconds
        if value >= 1:
            value = int(value)
            return f"{value} {period}{'s' if value != 1 else ''} ago"
    
    return "just now"

#home page
@app.route('/')
def home():
    question = Question.query.order_by(desc(Question.created_at)).all()
    question_list = Question.query.order_by(desc(Question.created_at)).all()
    all_tags = []
    for q in question_list:
        if q.tags:
            tags = [tag.strip() for tag in q.tags.split(',') if tag.strip()]
            all_tags.extend(tags)
    tag_counter = Counter(all_tags)
    top_tags = [tag for tag, count in tag_counter.most_common(10)]
    departments = db.session.query(Question.department).distinct().all()
    department_tags = [dept[0] for dept in departments if dept[0]]
    return render_template('home.html',questions=question,top_tags=top_tags,
                               department_tags=department_tags,
                               )
#signup page
@app.route('/signup',methods=['POST','GET'])
def signup():
    if request.method=='POST':
        first_name=request.form['first_name']
        last_name=request.form['last_name']
        full_name=first_name+last_name
        username=request.form['username']
        email=request.form['email']
        c_id=request.form['college_id']
        password=request.form['password']
        hashed_password = generate_password_hash(password)
        department=request.form['department']
        year=request.form['year']
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('signup'))
        new_user=User(
            first_name=first_name,
            last_name=last_name,
            full_name=full_name,
            username=username,
            email=email,
            c_id=c_id,
            password=password,
            department=department,
            year=year
        )
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        session['user_email'] = new_user.email
        return redirect(url_for('otp_gene'))
    return render_template('login.html')
@app.route('/otp_gene')
def otp_gene():
    x = session.get('user_id')
    user_email = session.get('user_email')  
    if not user_email:
        flash("Session expired. Please sign up again.", "warning")
        return redirect(url_for('signup'))
    user_emails =user_email
    subject="Verification code"
    otp=random.randint(100000, 999999)
    user = User.query.get(x)
    user.otp = otp
    db.session.commit()
    body="Your verification code is "+str(otp)
    msg = Message(subject=subject, sender=app.config['MAIL_USERNAME'], recipients=[user_emails])
    msg.body = body
    try:
        mail.send(msg)
        flash('Mail sent successfully!', 'success')
    except Exception as e:
        flash(f'Something went wrong: {str(e)}', 'danger')
    return render_template('otp.html')

@app.route('/otp', methods=['POST', 'GET'])
def otp():
    if request.method == 'POST':
        flash('OTP sent', 'success')
        otp = request.form['otp']
        x = session.get('user_id')
        user = User.query.get(x)

        if user and int(otp) == int(user.otp):
            session['user_id'] = user.id
            session['user_email'] = user.email
            user.otp = None  # clear OTP after use
            user.verify=True
            db.session.commit()
            flash ('Welcome to ask Lpu!', 'success')
            return redirect(url_for('index'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('otp'))
    return render_template('otp.html')


#login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # Regular user login
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            session['user'] = email
            session['user_id'] = user.id
            if user.verify==True:
                return redirect(url_for('index'))
            else:
                x = session.get('user_id')
                user=user.query.get(x)
                db.session.delete(user)
                db.session.commit()
                return redirect(url_for('signup'))
        else:
            flash('Invalid credentials!', 'danger')
    else:
        return render_template('login.html')
    return render_template('login.html')
#index page
@app.route('/index')
def index():
    user_id = session.get('user_id')
    if user_id:
        question = Question.query.order_by(desc(Question.created_at)).all()
        x = session.get('user_id')
        user=User.query.get(x)
        notifications = Notification.query.filter_by(recipient_id=user.id).order_by(desc(Notification.created_at)).all()
        question_list = Question.query.order_by(desc(Question.created_at)).all()
        all_tags = []
        for q in question_list:
            if q.tags:
                tags = [tag.strip() for tag in q.tags.split(',') if tag.strip()]
                all_tags.extend(tags)
        tag_counter = Counter(all_tags)
        top_tags = [tag for tag, count in tag_counter.most_common(10)]
        departments = db.session.query(Question.department).distinct().all()
        department_tags = [dept[0] for dept in departments if dept[0]]
        return render_template('index.html',user=user,questions=question,top_tags=top_tags,
                               department_tags=department_tags,
                               notifications=notifications)
    else:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))
#search
@app.route('/search', methods=['GET'])
def search():
    queryy = request.args.get('query', '').strip() # Get search query from URL parameters
    print(queryy)
    if queryy:
        # Searching for questions and answers based on query (could be title, description, or tags)
        questions = Question.query.filter(
            (Question.title.ilike(f'%{queryy}%')) |
            (Question.description.ilike(f'%{queryy}%')) |
            (Question.tags.ilike(f'%{queryy}%'))
        ).all()
        
        answers = Answer.query.filter(
            Answer.content.ilike(f'%{queryy}%')
        ).all()
    else:
        questions = []
        answers = []
    return render_template('search_results.html', questions=questions, answers=answers, query=queryy)


@app.route('/question/<int:question_id>')
def question_view(question_id):
    question = Question.query.get_or_404(question_id)
    answers = Answer.query.filter_by(question_id=question_id).all()
    return render_template('question_view.html', question=question, answers=answers)
#ask
@app.route('/ask')
def ask():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('ask.html',user=user)    

@app.route('/askques', methods=['GET', 'POST'])
def askques():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        tags = request.form.get('tags', '').strip()
        department = request.form.get('department', '').strip()
        subject = request.form.get('subject', '').strip()
        final = title +" " + description +" "+ tags
        if is_question_safe(final)==False:
            flash("You have asked an inappropriate question!", "danger")
            return redirect(url_for('ask'))  # Reload the same form with message
        else:
            new_question = Question(
            title=title,
            description=description,
            tags=tags,
            department=department,
            subject=subject,
            user_id=session['user_id']
            )
            db.session.add(new_question)
            db.session.commit()
            flash("Question posted successfully!", "success")
            return redirect(url_for('index'))
    return render_template('ask.html')

#answer
@app.route('/answer/<int:question_id>',methods=['POST','GET'])
def answer(question_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method=='POST':
        question_id=question_id
        content=request.form.get('content')
        new_answer=Answer(
            content=content,
            user_id=session['user_id'],
            question_id=question_id
        )
        print(content)
        db.session.add(new_answer)
        db.session.commit()
        question = Question.query.get(question_id)
        if question.user_id != session['user_id']:
            notify = Notification(
            recipient_id=question.user_id,
            sender_id=session['user_id'],
            message='answered your question',
            link=url_for('index') + f"?question_id={question_id}"
        )
        
            db.session.add(notify)
            db.session.commit()
            flash("Answer posted successfully!", "success")
    return redirect(url_for('index',question_id=question_id))
#notification
# @app.route('/notifications')
# def view_notifications():
#     user = User.query.get(session['user_id'])
#     notifications = Notification.query.filter_by(recipient_id=user.id).order_by(desc(Notification.created_at)).all()
#     return render_template('index.html', notifications=notifications, user=user)
#delete answer
@app.route('/delete_comment/<int:answer_id>', methods=['POST'])
def delete_answer(answer_id):
    answer=Answer.query.get(answer_id)
    db.session.delete(answer)
    db.session.commit()
    flash("Answer deleted successfully!", "success")
    return redirect(url_for('index'))

@app.route('/delete/<int:question_id>')
def delete_q(question_id):
    question = Question.query.get_or_404(question_id)

    # Delete all notifications related to answers of this question
    for answer in question.answers:
        Notification.query.filter_by(link=url_for('index') + f"?question_id={question.id}").delete()

    # Delete the question (this will also delete its answers if relationship is set to cascade)
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", "success")
    return redirect(url_for('index'))

@app.route('/vote/<int:answer_id>/upvote', methods=['POST'])
def upvote(answer_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    
    answer = Answer.query.get_or_404(answer_id)
    user = User.query.get(session['user_id'])
    
    # Check for an existing vote
    stmt = db.select(votes_association).where(
        votes_association.c.user_id == user.id,
        votes_association.c.answer_id == answer.id
    )
    existing_vote = db.session.execute(stmt).first()

    if existing_vote:
        if existing_vote.vote_type == 'upvote':
            # User is canceling their upvote
            delete_stmt = db.delete(votes_association).where(
                votes_association.c.user_id == user.id,
                votes_association.c.answer_id == answer.id
            )
            db.session.execute(delete_stmt)
        else:
            # User is changing their downvote to an upvote
            update_stmt = db.update(votes_association).where(
                votes_association.c.user_id == user.id,
                votes_association.c.answer_id == answer.id
            ).values(vote_type='upvote')
            db.session.execute(update_stmt)
    else:
        # User is casting a new upvote
        insert_stmt = db.insert(votes_association).values(
            user_id=user.id, 
            answer_id=answer.id, 
            vote_type='upvote'
        )
        db.session.execute(insert_stmt)

    db.session.commit()
    return jsonify({'score': answer.score})

@app.route('/vote/<int:answer_id>/downvote', methods=['POST'])
def downvote(answer_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    
    answer = Answer.query.get_or_404(answer_id)
    user = User.query.get(session['user_id'])

    # Check for 
    stmt = db.select(votes_association).where(
        votes_association.c.user_id == user.id,
        votes_association.c.answer_id == answer.id
    )
    existing_vote = db.session.execute(stmt).first()

    if existing_vote:
        if existing_vote.vote_type == 'downvote':
            # User is canceling their downvote
            delete_stmt = db.delete(votes_association).where(
                votes_association.c.user_id == user.id,
                votes_association.c.answer_id == answer.id
            )
            db.session.execute(delete_stmt)
        else:
            # User is changing their upvote to a downvote
            update_stmt = db.update(votes_association).where(
                votes_association.c.user_id == user.id,
                votes_association.c.answer_id == answer.id
            ).values(vote_type='downvote')
            db.session.execute(update_stmt)
    else:
        # User is casting a new downvote
        insert_stmt = db.insert(votes_association).values(
            user_id=user.id, 
            answer_id=answer.id, 
            vote_type='downvote'
        )
        db.session.execute(insert_stmt)
    db.session.commit()
    return jsonify({'score': answer.score})


#profile
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    questions = Question.query.filter_by(user_id=user.id).all()
    answers = Answer.query.filter_by(user_id=user.id).all()

    total_upvotes = 0
    accepted_answers = 0

    for answer in answers:
        upvotes = db.session.query(votes_association).filter_by(answer_id=answer.id, vote_type='upvote').count()
        downvotes = db.session.query(votes_association).filter_by(answer_id=answer.id, vote_type='downvote').count()
        score = upvotes - downvotes

        total_upvotes += upvotes
        if score >= 1:
            accepted_answers += 1

    total_answers = len(answers)
    accept_rate = round((accepted_answers / total_answers) * 100) if total_answers > 0 else 0

    return render_template(
        'profile.html',
        user=user,
        questions=questions,
        answers=answers,
        total_upvotes=total_upvotes,
        accept_rate=accept_rate
    )
@app.route('/update_bio',methods=['POST'])
def update_bio():
    user = User.query.get(session['user_id'])
    user.bio = request.form.get('bio')
    db.session.commit()
    return redirect(url_for('profile'))


@app.route('/update_profile')
def update_profile():
    user = User.query.get(session['user_id'])

    return render_template('update_profile.html',user=user)
#log out page
@app.route('/update',methods=['POST'])
def update():
    first_name=request.form.get('first_name')
    last_name=request.form.get('last_name')
    full_name=first_name+' '+last_name
    department=request.form.get('department')
    year=request.form.get('year')
    bio=request.form.get('bio')
    interest=request.form.get('interests_input')
    skills=request.form.get('skills_input')
    location=request.form.get('location')
    course=request.form.get('course')

    update=User(
        full_name=full_name,
        department=department,
        year=year,
        bio=bio,
        interest=interest,
        skiils=skills,
        location=location,
        course=course
    )
    update.id=session['user_id']
    db.session.merge(update)
    db.session.commit()

    return redirect(url_for('profile'))

#clear notification
@app.route('/clear_notification')
def clear_notification():
    user = User.query.get(session['user_id'])
    unread_notifications = Notification.query.filter_by(recipient_id=user.id, is_read=False).all()
    for notification in unread_notifications:
        notification.is_read = True
    db.session.commit()
    return redirect(url_for('index'))
@app.route('/delete')
def delete():
    user = User.query.get(session['user_id'])
    Notification.query.filter((Notification.sender_id == user.id) | (Notification.recipient_id == user.id)).delete()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/comment', methods=['POST'])
def comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = request.form.get('comm')
    answer_id = request.form.get('answer_id')

    if not content or not answer_id:
        flash("Comment or answer reference missing!", "danger")
        return redirect(url_for('index'))
    new_comment = Comment(
        content=content,
        answer_id=int(answer_id),
        user_id=session['user_id']
    )
    db.session.add(new_comment)
    db.session.commit()

    # Optional: Add notification
    answer = Answer.query.get(answer_id)
    if answer.user_id != session['user_id']:
        notify = Notification(
            recipient_id=answer.user_id,
            sender_id=session['user_id'],
            message='commented on your answer',
            link=url_for('index') + f"?question_id={answer.question_id}"
        )
        db.session.add(notify)
        db.session.commit()
    flash("Comment posted successfully!", "success")
    return redirect(url_for('index', question_id=answer.question_id))


@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})

    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join('static/uploads', filename)
        file.save(filepath)
        file_url = url_for('static', filename='uploads/' + filename)
        return jsonify({'success': True, 'url': file_url})

    return jsonify({'success': False, 'error': 'Unknown error'})
   
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/logout')
def logout():

    session.pop('user',None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This creates all tables from your models
    app.run(debug=False)
