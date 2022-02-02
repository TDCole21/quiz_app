from functions import *

######################################################################################################################################################################
# HOME
######################################################################################################################################################################

# Template login page
@app.route('/')
@app.route('/index')
@app.route('/home')
def home():
    return render_template(
        "misc/index.html",
        name="Home"
    )


######################################################################################################################################################################
# LOGIN
######################################################################################################################################################################

# If you are not currently logged in, it directs you to the login html page, otherwise it redirects you to the profile page.
@app.route('/login')
def login_page():       
    if not 'loggedin' in session:      
        return render_template(
            "users/login.html",
            name="Login"
        )

    else:
        return redirect(url_for('profile'))

# From the login page, this function will take the user information, check it against a database, and if it exists, then will login the user into the session
@app.route('/login/submit', methods=['GET', 'POST'])
def login_attempt():
    if request.method == 'POST':
        # Checking if user has tried to login using an email or username
        if email(request.form.get('userDetails')):
            login_via = "User_Email"

        else:
            login_via = "Username"

        # Checks if the Username or Email exists in the Users database
        if check_db(
            "User_ID",
            "Users",
            login_via + " = \"" + request.form.get('userDetails') + "\""
        ):
            # Checks if the input password, when hashed, matches the one on the database
            if check_password_hash(
                get_entry_fromDB(
                    "User_Password",
                    "Users",
                    login_via + " = \"" + request.form.get('userDetails') + "\""
                )['User_Password'],
                request.form.get('password')
            ):
                # Get user information
                account = get_entry_fromDB(
                    "User_ID, Username, User_Email, User_Admin",
                    "Users",
                    login_via + " = \"" + request.form.get('userDetails') + "\""
                )

                # Enters user information in the session
                login_session(
                    account["User_ID"],
                    account["Username"],
                    account["User_Email"],
                    account["User_Admin"]
                )

                # Login is successful, so redirect user to the profile page
                return redirect(url_for('profile'))
            
            # User exists, but password is wrong. Login failed
            else:
                flash('Please check your login details and try again.')
        
        # Username/User Email does not exist in the database
        else:
            flash('This account does not exist.')
            flash('register')     

    # If no post method was used, or the user was failed to login, then they're redirected to the login page 
    return redirect(url_for('login_page'))

# This is accessed via the nav-bar and logs the user out of the sesion
@app.route('/logout')
def logout_user():   
    # Logs user out of the current session      
    logout_session()
    flash('You have successfully logged out')   
    # Redirects user to login page
    return redirect(url_for('login_page'))

# This is accesed via the nav-bar and takes the user to the forgot password html page
@app.route('/forgot_password')
def forgot_password():   
    # Redirects to forgot password html page
    return render_template(
        "users/forgot_password.html",
        name="Forgot Password"
    )


######################################################################################################################################################################
# USERS
######################################################################################################################################################################

# Profile login page
@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # Redirects to profile page with user information from session
        return render_template(
            "users/profile.html",
            username=session['username'],
            email=session['email'],
            name="Profile"
        )
    # User is not loggedin redirect to login page
    return redirect(url_for('login_page'))

# Deletes the user from the database
@app.route('/profile/delete', methods=['GET', 'POST'])
def profile_delete():
    if request.method == "POST":
        # Deletes user from the database based on the username
        delete_db_entry(
            "Users",
            "Username = \"" + session['username'] + "\""
        )
        # Logs the user out of the session
        logout_session()
        flash('You have successfully deleted your account')     

        # Redirects user to home page
        return redirect(url_for('home'))
    
    # Redirects user to home page, with non-user message
    flash('Naughty naughty, you need an account to do that')   
    return redirect(url_for('home'))

# Updates the user's email in the database and session
@app.route('/profile/email/update', methods=['GET', 'POST'])
def email_update():
    if request.method == "POST":
        # Checks if the requested email already exists in the database
        if check_db(
            "User_ID",
            "Users",
            "User_Email = \"" + request.form.get('new_email') + "\""
        ):
            flash('That email is already in use.')

        else:
            # Updates the database entry with the new email address
            update_db_entry(
                "Users",
                "User_Email = \"" + request.form.get('new_email') + "\"",
                "User_Email = \"" + session['email'] + "\""
            )
            # Updates the session with the new email address
            session['email'] = request.form.get('new_email')

    # Redirects back to the profile page
    return redirect(url_for('profile'))

# Updates the user's username in the database and session
@app.route('/profile/username/update', methods=['GET', 'POST'])
def username_update():
    if request.method == "POST":
        # Checks is the username contains an @ symbol. I use the @ symbol to differentiate between user email and username
        if email(request.form.get('new_username')):
            flash('A username cannot contain an @ character.')

        # Checks if the new username already exists in the database
        elif check_db(
            "User_ID",
            "Users",
            "Username = \"" + request.form.get('new_username')+"\""
        ):
            flash('That username is already in use.')

        else:
            # Updates the username entry in the database with the new username, using the session email as the identifier
            update_db_entry(
                "Users",
                "Username = \"" + request.form.get('new_username')+"\"",
                "Username = \"" + session['username']+"\""
            )
            # Updates the session with the new username
            session['username'] = request.form.get('new_username')

    # Redirects user to profile page
    return redirect(url_for('profile'))

# Updates the user's password in the database
@app.route('/profile/password/update', methods=['GET', 'POST'])
def password_update():
    if request.method == "POST":
        # Updates the user's password in the database, using the session email as the identifier
        update_db_entry(
            "Users",
            "User_Password = \"" + generate_password_hash(request.form.get('new_password') + "\"", method='sha256'),
            "User_Email = \"" + session['email']+"\""
        )

    # Redirects user to the profile page
    return redirect(url_for('profile'))

######################################################################################################################################################################
# REGISTER
######################################################################################################################################################################

# Create account template page
@app.route('/register')
def register():
    # Checks if the person accessing the url link is logged into the session
    if not 'loggedin' in session:
        # If not logged in, redirects user to the register page
        return render_template(
            "users/register.html",
            name="Register"
        )

    else:
        # If the user is already logged in, then they are redirected to their profile page
        return redirect(url_for('profile'))

# This creates a new entry into the Users table in the database, using the information submitted via the form by the user
@app.route('/register/submit', methods=['GET', 'POST'])
def user_create():
    if request.method == "POST":
        # Checks if the username has an @ character. My backend differentiates emails and usernames based on this
        if email(request.form.get('username')):
            flash('Signup failed. A username cannot contain an @ character.')

        # Checks is the username or email already exists in the database
        elif check_db(
            "User_ID",
            "Users",
            "Username = \"" + request.form.get('username') + "\" OR User_Email = \"" + request.form.get('email') + "\""
        ):
            flash('That account is already in use.')
            flash('login')

        else:
            # checks if the password and repeat password are the same
            if duplicate(
                request.form.get('password'),
                request.form.get('password-repeat')
            ):
                # Inserts the new values into the Users table in the database. By default the user is not an admin (admin=0)
                insert_db_entry(
                    "Users",
                    "Username, User_Email, User_Password, User_Admin",
                    "\"" + request.form.get('username') + "\", \"" + request.form.get('email') + "\", \"" + generate_password_hash(request.form.get('password'), method='sha256') + "\", 0"
                )

                # This then grabs the information that was just entered into the database
                account = get_entry_fromDB(
                    "User_ID, Username, User_Email, User_Admin",
                    "Users",
                    "User_Email = \"" + request.form.get('email') + "\""
                )
                
                # Logs the user into the session
                login_session(
                    account["User_ID"],
                    account["Username"],
                    account["User_Email"],
                    account["User_Admin"]
                )
                # Redirects the user to their profile page
                return redirect(url_for('profile'))

            # If the user failed the password repetition
            else:
                flash('Signup failed. Passwords were different.')
                # potentially include a return that will keep the name   
                
    # If the user nativgated to the url without a post method, or failed to create an account, they're redirected to the register page                   
    return redirect(url_for('register'))


######################################################################################################################################################################
# QUIZ
######################################################################################################################################################################

# HTML template for the quizzes (to host, join or make/edit)
@app.route('/quiz')
def quiz():
    return render_template(
        "quiz/quiz.html",
        name="Quiz"
    )

# MAKE/EDIT     ############################################################################

# HTML template for quiz maker/editor page. The page will display info on all quizes. The page will redirect those who aren't admins.
@app.route('/quiz_maker')
def quiz_maker():
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    # Gets all quizzes from the Quiz table
    quiz_info= get_entries_fromDB(
        "Quiz_ID, Quiz_Name",
        "Quiz",
        "Quiz_Name IS NOT NULL"
    )

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/make_a_quiz/quiz_maker.html",
        name="Quiz Maker",
        quiz_info=quiz_info
    )

# QUIZ #

# Creates a basic entry into the Quiz table, using only the Quiz Name
@app.route('/create_quiz', methods=['GET', 'POST'])
def create_quiz():
    # Check to see if the user is an admin, and redirects to the home page if not
    if authorisation():
        return redirect(url_for('home'))

    if request.method == "POST":
        # Checks if a Quiz already has the name
        if check_db(
            "Quiz_ID",
            "Quiz",
            "Quiz_Name = \"" + request.form.get('quiz_name') + "\""
        ):
            # Redirects user to the Quiz maker/editor page
            flash('That Quiz name is already in use.')
            return redirect(url_for('quiz_maker'))

        else:
            # Creates a new entry in the Quiz table using the quiz name form the form
            insert_db_entry(
                "Quiz",
                "Quiz_Name, Active",
                "\"" + request.form.get('quiz_name') + "\", '0'"
            )

            # Gets information about the newly created quiz
            quiz_info = get_entry_fromDB(
                "Quiz_ID",
                "Quiz",
                "Quiz_Name = \"" + request.form.get('quiz_name') + "\""
            )

    # Redirects user to the Quiz template page for the newly created Quiz
    return redirect(url_for(
        'quiz_template',
        quiz_ID=quiz_info['Quiz_ID']
    ))


# This will remove a Quiz from the database
@app.route('/delete_quiz/<quiz_ID>')
def delete_quiz(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    # Checks to see if the Quiz exists
    if not check_db(
        "Quiz_ID",
        "Quiz",
        "Quiz_ID = " + quiz_ID
    ):
        flash("This Quiz does not exist")

    else:
        # Removes the Quiz from the database based off the Quiz_ID
        delete_db_entry(
            "Quiz",
            "Quiz_ID = " + quiz_ID
        )

    # Redirects the user to the Quiz Maker/Editor page
    return redirect(url_for('quiz_maker'))


# ROUNDS #

# This will create a new Round that is related to a specific Quiz
@app.route('/create_round/<quiz_ID>', methods=['GET', 'POST'])
def create_round(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    # Checks to see if the Quiz exists  
    if not check_db(
        "Quiz_ID",
        "Quiz",
        "Quiz_ID = " + quiz_ID
    ):
        flash("This Quiz does not exist")
        # Redirects user to the Quiz Maker/Editor page
        return redirect(url_for('quiz_maker'))

    if request.method == "POST":
        # Checks if there isn't already a round with the same name in the current Quiz
        if check_db(
            "Round_ID",
            "Rounds",
            "Round_Name = \"" + request.form.get('round_name') + "\" AND Quiz_ID = " + str(quiz_ID)
        ):
            flash("This Round name already exists in this Quiz")

        else:
            # Calculates the number of Round for a given Quiz_ID
            noOfRounds = len(get_entries_fromDB(
                "Round_ID",
                "Rounds",
                "Quiz_ID = " + quiz_ID
            ))

            # Inserts the Round into the Rounds table, using the noOfRounds +1 as its unique identifier
            insert_db_entry(
                "Rounds",
                "Quiz_ID, Round_Name, Round_Order",
                quiz_ID + ", \"" + request.form.get('round_name') + "\", " + str(noOfRounds + 1)
            )

            # Retrieves the new Round information from the Rounds table, using the noOfRounds +1 as its unique identifier
            round_info = get_entry_fromDB(
                "Round_ID",
                "Rounds",
                "Round_Order = " + str(noOfRounds + 1 ) + " AND Quiz_ID = " + str(quiz_ID)
            )
            
            # Redirects users to the Round template html page, specific to the Round just created
            return redirect(url_for(
                'round_template',
                round_ID=round_info['Round_ID']
            ))
    
    # If the URL was accessed with the correct authorisation, but without a POST method they're redicted to the Quiz template
    return redirect(url_for(
        'quiz_template',
        quiz_ID=quiz_ID))

# This function will delete a round from the database, based on the Round ID.
# I need to update this function so that the round_ID isn't in the url, although the authorisation check means it can't be actioned by non-admins
@app.route('/delete_round/<round_ID>')
def delete_round(round_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    # Retrieves the Round information from the Rounds table based on the Round_ID
    round_Info = get_entry_fromDB(
        "Quiz_ID, Round_Order",
        "Rounds",
        "Round_ID = " + round_ID
    )

    # Deletes the Round from the Rounds table in the database based off the Round_ID
    delete_db_entry(
        "Rounds",
        "Round_ID = " + round_ID
    )

    # Calculates the number of Rounds for a given Quiz_ID
    noOfRounds = len(get_entries_fromDB(
        "Round_ID",
        "Rounds",
        "Quiz_ID = "+ str(round_Info['Quiz_ID'])
    ))

    # For all other Rounds with Round_Orders greater than the one that was deleted, their Round_Order is reduced by one
    for i in range(round_Info['Round_Order'], noOfRounds + 1):
        update_db_entry(
            "Rounds",
            "Round_Order = " + str(i),
            "Round_Order = " + str(i+1)
        )

    # Redirects users to the Quiz template based on the Quiz_ID
    return redirect(url_for(
        'quiz_template',
        quiz_ID = round_Info['Quiz_ID']
    ))

# QUESTIONS #

# This will create a Question associated with a specific Round
@app.route('/create_question/<round_ID>')
def create_question(round_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    # Calculates the number of Questions for a given Round_ID
    noOfQuestions = len(get_entries_fromDB(
        "Question_ID",
        "Questions",
        "Round_ID = " + round_ID
    ))

    # Creates a new Question in the database, using the noOfQuestions for the Question Order
    insert_db_entry(
        "Questions",
        "Round_ID, Question_Order, Question_Tag",
        round_ID + ", " + str(1 + noOfQuestions) + ", \"Question " + str(1 + noOfQuestions) + "\""
    )

    # Retrieves the Question information from the database for the Question just created
    question_info = get_entry_fromDB(
        "Question_ID",
        "Questions",
        "Round_ID = " + round_ID + " AND Question_Order = " + str(1 + noOfQuestions)
    )

    # Redirects user to the Question template for the newly created Question
    return redirect(url_for(
        'question_template',
        question_ID = question_info['Question_ID']
    ))

# This will delete a specific question, and depending on the page where it was actioned, will return the user to the appropriate page
@app.route('/delete_question/<source_point>/<question_ID>')
def delete_question(source_point, question_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    # Retreives Question information based on the Question_ID, before the question is deleted.
    question_info = get_entry_fromDB(
        "Round_ID, Question_Order",
        "Questions",
        "Question_ID = " + question_ID
    )

    # Removes the Question from the Questions table in the database
    delete_db_entry(
        "Questions",
        "Question_ID = " + question_ID
    )

    # Calculates the number of Questions for a given Round
    noOfQuestions = len(get_entry_fromDB(
        "Question_ID",
        "Questions",
        "Round_ID = " + str(question_info['Round_ID'])
    ))

    # Updates all other Question orders for that Round
    for i in range(question_info['Question_Order'], noOfQuestions + 1):
        update_db_entry(
            "Questions",
            "Question_Order = " + str(i),
            "Question_Order = " + str(i+1)
        )

    # Checks if the User deleted the Question from the Quiz overview
    if source_point == "quiz":
        # Retreives Quiz information based on the Round_ID from the Question information
        quiz_info = get_entry_fromDB(
            "Quiz_ID",
            "Rounds",
            "Round_ID = " + str(question_info['Round_ID'])
        )

        # Redirects user to the Quiz template for the Quiz the Question was associated with
        return redirect(url_for(
            'quiz_template',
            quiz_ID = quiz_info['Quiz_ID']
        ))
    
    # Checks if the User deleted the Question from the Round or Question overview
    else:
        # Redirects user to the Quiz template for the Round the Question was associated with
        return redirect(url_for(
            'round_template',
            round_ID = question_info['Round_ID']
        ))        

# PARTICIPANTS #
 
# This will insert selected users into the participants table for a given Quiz
@app.route('/add_participants/<quiz_ID>', methods=['GET', 'POST'])
def add_participants(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    if request.method == "POST":
        # Cycle through the list of users submitted from the form
        for i in request.form.getlist('user_ID'):
            # Insert the user into the participants table
            insert_db_entry(
                "Participants",
                "User_ID, Quiz_ID",
                i + ", " + quiz_ID
            )

    # Redirect user to the Quiz template page for the current Quiz
    return redirect(url_for(
        'quiz_template',
        quiz_ID = quiz_ID
    ))

# This will remove selected users from the participants table in the database, for a given Quiz
@app.route('/remove_participants/<quiz_ID>', methods=['GET', 'POST'])
def remove_participants(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))

    if request.method == "POST":
        # Cycle through the list of users submitted from the form
        for i in request.form.getlist('username'):
            
            # Retrieve the User_ID from the Username provided by the form
            user_info= get_entry_fromDB(
                "User_ID",
                "Users",
                "Username = \"" + i + "\""
            )

            # Delete the user into the participants table
            delete_db_entry(
                "Participants",
                "User_ID = " + str(user_info['User_ID']) + " AND Quiz_ID = " + quiz_ID
            )

    # Redirect user to the Quiz template page for the current Quiz
    return redirect(url_for(
        'quiz_template',
        quiz_ID = quiz_ID
    ))

# EDIT     ############################################################################

# QUIZ #

# This will display an overview page for the Quiz. Displaying basic information on all its participants, rounds and questions.
@app.route('/quiz_template/<quiz_ID>')
def quiz_template(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))    

    # Checks to see if the Quiz exists
    if not check_db(
        "Quiz_ID",
        "Quiz",
        "Quiz_ID = " + quiz_ID
    ):
        # Redirects users to the Quiz maker/editor overview page if the Quiz doesn't exist
        flash("This Quiz does not exist")
        return redirect(url_for('quiz_maker'))

    # Retrieves information about the Quiz based of the Quiz_ID
    quiz_info = get_entry_fromDB(
        "Quiz_ID, Quiz_Name, Quiz_Description",
        "Quiz",
        "Quiz_ID = " + quiz_ID
    )

    # Collects information on all the Rounds associated with the Quiz
    round_info= get_entries_fromDB(
        "Round_ID, Round_Name, Round_Order",
        "Rounds",
        "Quiz_ID = " + quiz_ID
    )

    # Sorts the dictionaries of Rounds in order of their Round_Order
    round_info = sorted(round_info, key=lambda k: k['Round_Order']) 

    # Create blank dictionary to collate all Questions
    question_info = []
    # Collects information on all the Questions associated with each Round in the Quiz
    for i in round_info:
        # For the given round, add all associated questions to a tempoary dictionary
        questions_per_round = get_entries_fromDB(
            "Question_ID, Round_ID, Question_Order, Question_Tag",
            "Questions",
            "Round_ID = " + str(i['Round_ID'])
        )

        # Sort the dictionary of Questions in order of the Question_Order
        questions_per_round = sorted(questions_per_round, key=lambda k: k['Question_Order']) 
        # Append the ordered dictionary to the overall list of Questions
        question_info.append(questions_per_round)

    # Returns all users who aren't already in the participant table
    user_info = compare_two_tables(
        "Username, User_ID",
        "Users",
        "User_ID",
        "Participants",
        "Quiz_ID = " + quiz_ID
    )

    # Returns all users from the participant table, whilst grabbing their associated Username from the Users table
    participant_info = common_values_not_unique(
        "Username",
        "Users",
        "User_ID",
        "Participants",
        "Quiz_ID = " + quiz_ID
    )

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/make_a_quiz/quiz_template.html",
        name="Quiz Template",
        quiz_info=quiz_info, 
        round_info=round_info,
        question_info=question_info,
        user_info=user_info,
        participant_info=participant_info
    )

# This will change the Quiz name to something else unique
@app.route('/update_quiz_name/<quiz_ID>', methods=['GET', 'POST'])
def update_quiz_name(quiz_ID):
    if request.method == "POST":
        # Checks if the new Quiz name is unique
        if check_db(
            "Quiz_ID",
            "Quiz",
            "Quiz_Name = \"" + request.form.get('new_quiz_name') + "\""
        ):
            # If the Quiz name is already in use, then the Quiz name is not updated
            flash('That Quiz name is already in use.')

        else:
            # If unqiue, then the Quiz Name is updated
            update_db_entry(
                "Quiz",
                "Quiz_Name = \"" + request.form.get('new_quiz_name') + "\"",
                "Quiz_ID = "+ quiz_ID
            )

    # Redirects user to Quiz template 
    return redirect(url_for(
        'quiz_template',
        quiz_ID=quiz_ID
    ))

# This will change the Quiz name to something else unique
@app.route('/update_quiz_description/<quiz_ID>', methods=['GET', 'POST'])
def update_quiz_description(quiz_ID):
    if request.method == "POST":
        # If unqiue, then the Quiz Name is updated
        update_db_entry(
            "Quiz",
            "Quiz_Description = \"" + request.form.get('new_quiz_description').replace("\"", "") + "\"",
            "Quiz_ID = " + str(quiz_ID)
        )

    # Redirects user to Quiz template 
    return redirect(url_for(
        'quiz_template',
        quiz_ID=quiz_ID
    ))

# ROUNDS #

# This will display an overview page for the Round. Displaying it's associated Quiz and basic information on its questions.
@app.route('/round_template/<round_ID>')
def round_template(round_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    # Checks to see if a Round with the request Round_ID exists in the Rounds table in the database
    if not check_db(
        "Round_ID",
        "Rounds",
        "Round_ID = " + round_ID
    ):
        # If the Round does not exists, then the user is redirected to the Quiz Maker/Editor overview page
        flash("This Round does not exist")
        return redirect(url_for('quiz_maker'))

    # Uses an Inner Join to get all information required of the round
    round_info = get_values(
        "one",
        "SELECT "
            "Rounds.Round_ID, Rounds.Round_Name, Rounds.Round_Order, Rounds.Round_Description,"
            "Quiz.Quiz_ID, Quiz.Quiz_Name "
        "FROM ("
            "Rounds INNER JOIN Quiz ON Rounds.Quiz_ID = Quiz.Quiz_ID) "
        "WHERE "
            "Rounds.Round_ID = " + round_ID + ";"    
    )

    # Using the Round_ID, it retrieves information about the all the Questions associtate with the Round
    question_info = get_entries_fromDB(
        "Question_ID, Question_Order, Question_Tag",
        "Questions",
        "Round_ID = " + round_ID
    )
    # Sorts the dictionaries of Questions in order of their Question_Order
    question_info = sorted(question_info, key=lambda k: k['Question_Order']) 

    # Calculates the number of Rounds in the Quiz
    number_of_rounds = len(get_entries_fromDB(
        "Round_Order",
        "Rounds",
        "Quiz_ID = " + str(round_info['Quiz_ID']))
    )

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/make_a_quiz/round_template.html",
        name="Round Template",
        round_info = round_info,
        question_info=question_info,
        number_of_rounds=number_of_rounds,
    )


# This function will update the current Round's name, but only if the new name doesn't already exist for a Round in the associated Quiz
@app.route('/update_round_name/<round_ID>', methods=['GET', 'POST']) 
def update_round_name(round_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    if request.method == "POST":
        # Collects information for the given round
        round_info = get_entry_fromDB(
            "Quiz_ID, Round_ID",
            "Rounds",
            "Round_ID = " + round_ID
        )

        # Checks if the new Round name is alrerady in use in this Quiz
        if check_db(
            "Round_ID",
            "Rounds",
            "Round_Name = \"" + request.form.get('new_round_name') + "\" AND Quiz_ID = " + str(round_info['Quiz_ID'])
        ):
            # If there's already a Round with that name in the Quiz, the Round_Name is not updated
            flash("This Round name already exists in this Quiz")

        else:
            # If there's not already a Round with that name in the Quiz, the Round_Name is updated
            update_db_entry(
                "Rounds",
                "Round_Name = \"" + request.form.get('new_round_name') + "\"",
                "Round_ID = " + str(round_info['Round_ID'])
            )

    # The user is redirected to the Round template
    return redirect(url_for(
        'round_template',
        round_ID=str(round_info['Round_ID']))
    )

# This function will update the current Round's name, but only if the new name doesn't already exist for a Round in the associated Quiz
@app.route('/update_round_description/<round_ID>', methods=['GET', 'POST']) 
def update_round_description(round_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    if request.method == "POST":
        # If there's not already a Round with that name in the Quiz, the Round_Name is updated
        update_db_entry(
            "Rounds",
            "Round_Description = \"" + request.form.get('new_round_description').replace("\"", "") + "\"",
            "Round_ID = " + str(round_ID)
        )

    # The user is redirected to the Round template
    return redirect(url_for(
        'round_template',
        round_ID=str(round_ID)
    ))

# QUESTIONS #

# This will display a detailed overview page for the Question, with the ability to edit each aspect.
@app.route('/question_template/<question_ID>')
def question_template(question_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    # Uses an Inner Join to get all information required of the question
    question_info = get_values(
        "one",
        "SELECT "
            "Questions.Question_ID, Questions.Question_Order, Questions.Question, Questions.Correct_Answer, Questions.Points, Questions.Video_url, Questions.Image_url, Questions.Audio_url, Questions.Question_Tag, "
            "Rounds.Round_ID, Rounds.Round_Name, Rounds.Round_Order, "
            "Quiz.Quiz_ID, Quiz.Quiz_Name "
        "FROM (("
            "Rounds INNER JOIN Quiz ON Rounds.Quiz_ID = Quiz.Quiz_ID) "
            "INNER JOIN Questions ON Rounds.Round_ID = Questions.Round_ID) "
        "WHERE "
            "Questions.Question_ID = "+question_ID+";"    
    )

    # Calculates the amount of Questions associated with a Round
    noOfQuestions = len(get_entries_fromDB(
        "Question_ID",
        "Questions",
        "Round_ID = " + str(question_info['Round_ID'])
    ))
    
    # Checks if the current Question is the first in the round
    if int(question_info['Question_Order']) != 1:
        # Gets the Question_ID for the previous Question
        previous_question_info = get_entry_fromDB(
            "Question_ID",
            "Questions",
            "Question_Order = " + str(int(question_info['Question_Order'])-1)
        )
    
    # If it's the first Question
    else:
        # Creates a blank dictionary
        previous_question_info = dict()

    # Checks if the current Question is the last in the round
    if int(question_info['Question_Order']) != noOfQuestions:
        # Gets the Question_ID for the next Question
        next_question_info = get_entry_fromDB(
            "Question_ID",
            "Questions",
            "Question_Order = " + str(int(question_info['Question_Order'])+1)
        )
    # If it's the last Question of the round
    else:
        # Creates a blank dictionary
        next_question_info = dict()

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/make_a_quiz/question_template.html",
        name = "Question Editor",
        question_info = question_info,
        noOfQuestions = noOfQuestions,
        previous_question_info = previous_question_info,
        next_question_info = next_question_info
    )

# This will find out what field is being updated and upload that information to the database
@app.route('/update_question/<question_ID>', methods=['GET', 'POST'])
def update_question(question_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    if request.method == "POST":
        # Gets information from the HTML form  
        question_update = request.form.get('question_update')
        question_update_field = request.form.get('question_update_field')
        question_update = re.sub("watch?v=", "embed/", question_update)
        question_update = question_update.replace("\"","")

        # Format the submitted data to work depending on what was updated
        if re.search("Audio", question_update_field):
            question_update = re.sub("view", "preview", question_update)
        if re.search("Video", question_update_field):
            question_update = re.sub("watch\?v\=", "embed/", question_update)
  
        # Puts quotation marks either side of the question update
        if question_update != "NULL":
            question_update = "\"" + question_update + "\""

        # Updates the question in the database    
        update_db_entry(
            "Questions",
            question_update_field + " = " + question_update,
            "Question_ID = " + question_ID
        )

        # Redirects to the question template
        return redirect(url_for(
            'question_template',
            question_ID=question_ID
        ))


# This with update the question or round number orders
@app.route('/change_order/<ID>', methods=['GET', 'POST'])
def change_order(ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  
        
    if request.method == "POST":
        # Gets information from the HTML form 
        old_order = int(request.form.get("old_order"))
        new_order = int(request.form.get("new_order"))
        order_type = request.form.get("order_type")
        source_point = request.form.get("source_point")
        source_point_ID = request.form.get("source_point_ID")

        # If the new order is lower than the old order
        if old_order > new_order:
            # Create a list of numbers from the new order to the old order.
            # Python range needs to be range(x,y,s) where x<y and s is step. So making s=-1 you can have a reverse list.
            order = list(range(old_order-1, new_order-1, -1))
            # This is putting the current order to a placeholder value. No order should be 0, so is a safe placeholder value
            update_db_entry(
                order_type+"s",
                order_type+"_Order = 0",
                order_type+"_Order = " + str(old_order)
            )

            # This will shift all other orders up 1 from the "new order" to the "old order-1"
            for i in order:
                update_db_entry(
                    order_type+"s",
                    order_type+"_Order = " + str(int(i+1)),
                    order_type+"_Order = " + str(i)
                )

            # This then changes the order from the placeholder order, to the new one
            update_db_entry(
                order_type+"s",
                order_type+"_Order = " + str(new_order),
                order_type+"_Order = 0"
            )
    

        # If the new order is higher than the old order 
        else:
            # Create a list of numbers from the old order to the new order.
            order=list(range(old_order,new_order+1))
            # This is putting the current order to a placeholder value. No order should be 0, so is a safe placeholder value
            update_db_entry(
                order_type+"s",
                order_type+"_Order = 0",
                order_type+"_Order = " + str(old_order)
            )

            # This will shift all other orders down 1 from the "new order +1" to the "old order"
            for i in range(len(order)):
                update_db_entry(
                    order_type+"s",
                    order_type+"_Order = " + str(order[i-1]),
                    order_type+"_Order = " + str(order[i])
                )

            # This then changes the order from the placeholder order, to the new one
            update_db_entry(
                order_type+"s",
                order_type+"_Order = " + str(new_order),
                order_type+"_Order = 0"
            )

        # These three if/else statments will return the user back to the appropriate pages

        # If this function was called from the round edit page, then it'll return you to the round edit page
        if source_point == "round":
            return redirect(url_for(
                source_point+'_template',
                round_ID=source_point_ID
            ))
        
        # If this function was called from the question edit page, then it'll return you to the question edit page
        elif source_point == "question" :
            return redirect(url_for(
                source_point+'_template',
                question_ID=source_point_ID
            ))

        # If this function was called from anywhere else, then it'll return you to the quiz edit page    
        else :
            return redirect(url_for(
                source_point+'_template',
                quiz_ID=source_point_ID
            ))


# HOST     ############################################################################

# This will display an overview page showing all Quizzes
@app.route('/host_a_quiz')
def host_a_quiz():
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    # This will return a dictionary of all Quizzes with their Quiz_ID and Quiz_Name    
    quiz_info= get_entries_fromDB(
        "Quiz_ID, Quiz_Name",
        "Quiz",
        "Quiz_Name IS NOT NULL"
    )

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/host_a_quiz/host_a_quiz.html",
        name="Host a Quiz",
        quiz_info=quiz_info
    )

@app.route('/host_live_quiz/<quiz_ID>/start_quiz')
def start_quiz(quiz_ID):
    # This will lable a quiz as active
    if authorisation():
        return redirect(url_for('home'))  

    else:
        # This update the value of active to TRUE in the database for the quiz  
        update_db_entry(
            "Quiz",
            "Active = 1",
            "Quiz_ID = " + str(quiz_ID)
        )

        # This update the value of active to TRUE in the database for the round  
        update_db_entry(
            "Rounds",
            "Active = 1, Completed = 0",
            "Quiz_ID = " + str(quiz_ID) + " AND Round_Order=1"
        )

        # Redirects the user back to the host live quiz
        return redirect(url_for(
            'host_live_quiz',
            quiz_ID=quiz_ID
        ))

@app.route('/host_live_quiz/<quiz_ID>/start_round', methods=['GET', 'POST'])
def start_round(quiz_ID):
    # This will lable a quiz as active
    if authorisation():
        return redirect(url_for('home'))  

    elif request.method == 'POST':
        # This update the value of active to TRUE in the database for the round  
        update_db_entry(
            "Questions",
            "Active = 1, Completed = 0",
            "Round_ID = " + str(request.form.get('round_id')) + " AND Question_Order = 1"
        )

        # Redirects the user back to the host live quiz
        return redirect(url_for(
            'host_live_quiz',
            quiz_ID=quiz_ID
        ))
    
    # This is incase someone tries to be naughty
    else:
        flash("Naughty, naughty")
        return redirect(url_for('home'))  

# This will act also as end of round
@app.route('/host_live_quiz/<quiz_ID>/start_question', methods=['GET', 'POST'])
def start_question(quiz_ID):
    # This will lable a quiz as active
    if authorisation():
        return redirect(url_for('home'))  

    elif request.method == 'POST':
        # Sets the current question to no longer active
        update_db_entry(
            "Questions",
            "Active = 0, Completed = 1",
            "Question_ID = " + str(request.form.get('question_id'))
        )

        current_question_order = get_entry_fromDB(
            "Question_Order",
            "Questions",
            "Question_ID = " + str(request.form.get('question_id'))
        )

        round_questions = get_entries_fromDB(
            "Question_ID, Question_Order, Active, Completed",
            "Questions",
            "Round_ID = " + str(request.form.get('round_id'))
        )

        # Checking if the question is the last question of the round
        if len(round_questions) == int(current_question_order['Question_Order']):
            # Set the current round as completed and no longer active
            update_db_entry(
                "Rounds",
                "Active = 0, Completed = 1",
                "Round_ID = " + str(request.form.get('round_id'))
            )

            current_round_order = get_entry_fromDB(
                "Round_Order",
                "Rounds",
                "Round_ID = " + str(request.form.get('round_id'))
            )

            quiz_rounds = get_entries_fromDB(
                "Round_ID, Round_Order, Active, Completed",
                "Rounds",
                "Quiz_ID = " + str(quiz_ID)
            )

            # Checking if the round is the last round of the quiz
            if len(quiz_rounds) == int(current_round_order['Round_Order']):
                update_db_entry(
                    "Quiz",
                    "Active = 0, Completed = \"" + timestamp() + "\"",
                    "Quiz_ID = " + str(quiz_ID)
                )
            else:
                update_db_entry(
                    "Rounds",
                    "Active = 1, Completed = 0",
                    "Round_Order = " + str(int(current_round_order['Round_Order'])+1) + " AND Quiz_ID = " + str(quiz_ID)
                )
        else:
            update_db_entry(
                "Questions",
                "Active = 1",
                "Question_Order = " + str(int(current_question_order['Question_Order'])+1) + " AND Round_ID = " + str(request.form.get('round_id'))
            )    


        # Redirects the user back to the host live quiz
        return redirect(url_for(
            'host_live_quiz',
            quiz_ID=quiz_ID
        ))

    # This is incase someone tries to be naughty
    else:
        flash("Naughty, naughty")
        return redirect(url_for('home'))  

# This function will use the Quiz_ID, Round_ID and Question_ID to display the host view for the current question
@app.route('/host_live_quiz/<quiz_ID>', methods=['GET', 'POST'])
def host_live_quiz(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  

    else:
        # Gets information on the current Quiz based of the Quiz_ID
        quiz_info = get_entry_fromDB(
            "Quiz_ID, Quiz_Name, Quiz_Description, Active, Completed", 
            "Quiz", 
            "Quiz_ID = " + str(quiz_ID)
        )

        # Gets information about the completed rounds in this quiz.
        active_rounds = get_entries_fromDB(
            "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed", 
            "Rounds", 
            "(Completed = TRUE OR Active = TRUE) AND Quiz_ID = " + str(quiz_ID)
        )

        # Gets information about all the questions in the quiz
        all_questions = common_values_not_unique(
            "Question_ID, Round_ID, Question_Order, Question_Tag, Active, Completed", 
            "Questions",
            "Round_ID",
            "Quiz",
            "Quiz_ID = " + str(quiz_ID)
        )

        active_questions = []
        for question in all_questions:
            if (question['Completed'] == 1 or question['Active'] == 1):
                active_questions.append(question)


        # If the page has been loaded by selecting a specific question
        if request.method == 'POST':
            if request.form.get('question_id') is not None:
                question_info = get_entry_fromDB(
                    "Question_ID, Round_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Question_ID = " + str(request.form.get('question_id'))
                )

                # Gets information about the round that the user has selected
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed", 
                    "Rounds", 
                    "Round_ID = " + str(question_info['Round_ID'])
                )
            
            elif request.form.get('round_id') is not None:
                # Gets information about the round that the user has selected
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed", 
                    "Rounds", 
                    "Round_ID = " + str(request.form.get('round_id'))
                )

                question_info = None
        
        # If the page has been loaded by default, then it'll get information on the most recent question
        elif request.args.get('Question_ID', ''):
            submitted_question = str(request.args.get('Question_ID', ''))
            if any(str(d['Question_ID']) == submitted_question for d in active_questions):
                # Gets information on the current Question based of the Question_ID
                question_info = get_entry_fromDB(
                    "Question_ID, Round_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Question_ID = " + str(request.args.get('Question_ID', ''))
                )

                # Gets information about the round that is currently active
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed", 
                    "Rounds", 
                    "Round_ID = " + str(question_info['Round_ID'])
                )
            
            else:
                flash("Think you're smart?")
                return redirect(url_for('home')) 

        # If the page has been loaded by default, then it'll get information on the most recent question
        elif request.args.get('Round_ID', ''):
            submitted_round = str(request.args.get('Round_ID', ''))
            if any(str(d['Round_ID']) == submitted_round for d in active_questions):
                # Gets information on the current Question based of the Question_ID
                question_info = None

                # Gets information about the round that is currently active
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed", 
                    "Rounds", 
                    "Round_ID = " + str(submitted_round)
                )
            
            else:
                flash("Think you're smart?")
                return redirect(url_for('home')) 

        else:    
            # Gets information about the round that is currently active
            round_info = get_entry_fromDB(
                "Round_ID, Round_Name, Round_Order, Round_Description, Active, Completed",  
                "Rounds", 
                "Active = TRUE AND Quiz_ID = " + str(quiz_ID)
            )

            if(round_info is not None):
                # Gets information on the current Question based of the Question_ID
                question_info = get_entry_fromDB(
                    "Question_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Active = 1 AND Round_ID = " + str(round_info['Round_ID'])
                )

            else:
                question_info = None

        if question_info is None:
            answer_info = None

        else:
            # Fetch DB information about the Answers for that Question, including the correct answer and all submitted answers from users
            answer_info = common_values(
                "Users.Username, Answers.User_ID, Answers.Answer, Answers.Correct",
                "Answers",
                "Users",
                "Users.User_ID",
                "Answers.User_ID WHERE Question_ID = " + str(question_info['Question_ID'])
            )

        # Returns information for which users are ready to start the quiz
        participant_info = common_values(
            "Users.Username, Participants.Ready",
            "Users",
            "Participants",
            "Users.User_ID",
            "Participants.User_ID WHERE Quiz_ID = " + str(quiz_ID)
        )

        # Checks if all participants are ready, and if so makes start = True
        start = False
        if all(d['Ready'] == 1  for d in participant_info):
            start = True

        # Feeds data into HTML Jinja2 template
        return render_template(
            "quiz/host_a_quiz/host_live_quiz.html",
            name= quiz_info['Quiz_Name'],
            quiz_info = quiz_info,
            round_info = round_info,
            question_info = question_info,
            answer_info = answer_info,
            all_questions = all_questions,
            active_rounds = active_rounds,
            participant_info = participant_info,
            start = start
        )

# This function will update the database with whether the answer submitted by the user was correct or not
@app.route('/host_live_quiz/<quiz_ID>/mark_answer', methods=['GET', 'POST'])
def mark_answer(quiz_ID):
    # Check to see if the user is an admin
    if authorisation():
        return redirect(url_for('home'))  
        
    elif request.method == 'POST':
        # Updates the DB with whether the answer was correct or not
        update_db_entry(
            "Answers",
            "Correct = " + request.form.get('marked_answer'),
            "User_ID = " + str(request.form.get('user_ID')) + " AND Question_ID = " + str(request.form.get('question_ID'))
        )

        # Redirects the user back to the host live quiz
        return redirect(url_for(
            'host_live_quiz',
            quiz_ID=quiz_ID,
            Question_ID=request.form.get('question_ID')
        ))


# JOIN     ############################################################################

# This function will display a web page with information about all the quizzes
@app.route('/join_a_quiz')
def join_a_quiz():
    # Grabs information on all the quizzes
    quiz_info = get_entries_fromDB(
        "Quiz_ID, Quiz_Name, Active, Completed",
        "Quiz",
        "Quiz_Name IS NOT NULL"
    )

    participant_info = get_entries_fromDB(
        "Quiz_ID, User_ID",
        "Participants",
        "Quiz_ID IS NOT NULL"
    )

    # Feeds data into HTML Jinja2 template
    return render_template(
        "quiz/join_a_quiz/join_a_quiz.html",
        name = "Join a Quiz",
        quiz_info = quiz_info,
        participant_info = participant_info
    )

# This function will display the current active Quiz, Round or Question information
@app.route('/live_quiz/<quiz_ID>', methods=['GET', 'POST']) #maybe add user_ID into app route
def live_quiz(quiz_ID):
    # Check to see if the user is part of the quiz, and redirect to the home page if not
    if not check_db(
        "User_ID",
        "Participants",
        "User_ID = " + str(session['id']) + " AND Quiz_ID = " + str(quiz_ID)
    ):
        flash("Tonight's not your night, ask the host to add you to the Quiz")
        return redirect(url_for('home'))

    # If the User is a Participant in the Quiz, then this will grab the required information to display on the page.
    else:
        # Gets information on the current Quiz based of the Quiz_ID
        quiz_info = get_entry_fromDB(
            "Quiz_ID, Quiz_Name, Quiz_Description, Active, Completed", 
            "Quiz", 
            "Quiz_ID = " + str(quiz_ID)
        )

        # Gets information about the completed rounds in this quiz.
        active_rounds = get_entries_fromDB(
            "Round_ID, Round_Name, Round_Order", 
            "Rounds", 
            "(Completed = TRUE OR Active = TRUE) AND Quiz_ID = " + str(quiz_ID)
        )

        # Gets information about all the questions in the quiz
        all_questions = common_values_not_unique(
            "Question_ID, Round_ID, Question_Order, Question_Tag, Active, Completed", 
            "Questions",
            "Round_ID",
            "Quiz",
            "Quiz_ID = " + str(quiz_ID)
        )

        active_questions = []
        for question in all_questions:
            if (question['Completed'] == 1 or question['Active'] == 1):
                active_questions.append(question)


        # It'll find if the user is read or not
        ready = get_entry_fromDB(
            "Ready", 
            "Participants", 
            "Quiz_ID = " + str(int(quiz_info['Quiz_ID'])) + " AND User_ID = " + str(session['id'])
        )

        # If the page has been loaded by selecting a specific question
        if request.method == 'POST':
            if request.form.get('question_id') is not None:
                question_info = get_entry_fromDB(
                    "Question_ID, Round_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Question_ID = " + str(request.form.get('question_id'))
                )

                # Gets information about the round that the user has selected
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description", 
                    "Rounds", 
                    "Round_ID = " + str(question_info['Round_ID'])
                )
            
            elif request.form.get('round_id') is not None:
                # Gets information about the round that the user has selected
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description", 
                    "Rounds", 
                    "Round_ID = " + str(request.form.get('round_id'))
                )

                question_info = None
        
        # If the page has been loaded by default, then it'll get information on the most recent question
        elif request.args.get('Question_ID', ''):
            submitted_question = str(request.args.get('Question_ID', ''))
            if any(str(d['Question_ID']) == submitted_question for d in active_questions):
                # Gets information on the current Question based of the Question_ID
                question_info = get_entry_fromDB(
                    "Question_ID, Round_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Question_ID = " + str(request.args.get('Question_ID', ''))
                )

                # Gets information about the round that is currently active
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description", 
                    "Rounds", 
                    "Round_ID = " + str(question_info['Round_ID'])
                )
            
            else:
                flash("Think you're smart?")
                return redirect(url_for('home')) 

        # If the page has been loaded by default, then it'll get information on the most recent question
        elif request.args.get('Round_ID', ''):
            submitted_round = str(request.args.get('Round_ID', ''))
            if any(str(d['Round_ID']) == submitted_round for d in active_questions):
                # Gets information on the current Question based of the Question_ID
                question_info = None

                # Gets information about the round that is currently active
                round_info = get_entry_fromDB(
                    "Round_ID, Round_Name, Round_Order, Round_Description", 
                    "Rounds", 
                    "Round_ID = " + str(submitted_round)
                )
            
            else:
                flash("Think you're smart?")
                return redirect(url_for('home')) 

        else:    
            # Gets information about the round that is currently active
            round_info = get_entry_fromDB(
                "Round_ID, Round_Name, Round_Order, Round_Description", 
                "Rounds", 
                "Active = TRUE AND Quiz_ID = " + str(quiz_ID)
            )

            if(round_info is not None):
                # Gets information on the current Question based of the Question_ID
                question_info = get_entry_fromDB(
                    "Question_ID, Question_Order, Question, Correct_Answer, Points, Video_url, Image_url, Audio_url, Question_Tag, Active, Completed",
                    "Questions",
                    "Active = 1 AND Round_ID = " + str(round_info['Round_ID'])
                )

            else:
                question_info = None

        if(question_info is not None):
            # Get answer for the current Question
            answer_info = get_entries_fromDB(
                "User_ID, Answer", 
                "Answers", 
                "Question_ID = " +  str(question_info["Question_ID"]) 
            )
        else:
            answer_info = None


        # Feeds data into HTML Jinja2 template
        return render_template(
            "quiz/join_a_quiz/live_quiz.html",
            name= quiz_info['Quiz_Name'],
            quiz_info = quiz_info,
            round_info = round_info,
            question_info = question_info,
            answer_info = answer_info,
            all_questions = all_questions,
            active_rounds = active_rounds,
            ready = ready
        )

# This function will update the DB to say that the user is ready to start the Quiz
@app.route('/quiz_ready/<quiz_ID>/<user_ID>')
def quiz_ready(quiz_ID, user_ID):
    # Updates DB with Ready = 1
    update_db_entry(
        "Participants",
        "Ready = 1",
        "User_ID = " + str(user_ID) + " AND Quiz_ID = " + quiz_ID)

    # Redirects the user back to the Live Quiz page
    return redirect(url_for(
        'live_quiz',
        quiz_ID = quiz_ID,
    ))

# This function will update the DB to say that the user is no longer ready to start the Quiz
@app.route('/quiz_unready/<quiz_ID>/<user_ID>')
def quiz_unready(quiz_ID, user_ID):

    # Updates DB with Read = 0
    update_db_entry(
        "Participants", 
        "Ready = 0", 
        "User_ID = " + str(user_ID) + " AND Quiz_ID = " + quiz_ID
    )

    # Redirects the user back to the Live Quiz page
    return redirect(url_for(
        'live_quiz',
        quiz_ID = quiz_ID,
    ))


# This function will submit the users answer the the answers table in the DB
@app.route('/submit_answer', methods=['GET','POST'])
def submit_answer():
    if request.method == "POST":
        # This checks if the user has already submitted an answer before
        if check_db(
            "User_ID",
            "Answers",
            "User_ID = " + str(request.form.get("user_ID")) + " AND Question_ID = " + str(request.form.get("question_ID"))
        ):
            # This updates the Answers table with the new answer
            update_db_entry(
                "Answers",
                "Answer = \"" + request.form.get("new_answer").replace("\"", "") + "\", Correct = NULL, Timestamp = \"" + timestamp() + "\"",
                "User_ID = " + str(request.form.get("user_ID")) + " AND Question_ID = " + str(request.form.get("question_ID"))
            )

        # If this is the first answer being submitted
        else:
            # Insert the new answer into the table
            insert_db_entry(
                "Answers",
                "User_ID, Question_ID, Answer, Timestamp",
                str(request.form.get("user_ID")) + ", " + str(request.form.get("question_ID")) + ", \"" + request.form.get("new_answer").replace("\"", "") + "\", \"" + timestamp() + "\""
            )

        # Gets Round information from the current Question ID
        round_info = get_entry_fromDB(
            "Round_ID",
            "Questions",
            "Question_ID = " + str(request.form.get("question_ID"))
        )

         # Gets Quiz information from the current Question ID
        quiz_info = get_entry_fromDB(
            "Quiz_ID",
            "Rounds",
            "Round_ID = " + str(round_info['Round_ID'])
        )

        # Redirects user to the Live Quiz page
        return redirect(url_for(
            'live_quiz',
            quiz_ID = quiz_info['Quiz_ID'],
            Question_ID = str(request.form.get("question_ID"))
        ))

# Results     ############################################################################

# This will display the results page
@app.route('/results/<quiz_id>')
def results(quiz_id):
    # Feeds data into HTML Jinja2 template

    participant_info = get_entries_fromDB(
        "Quiz_ID, User_ID",
        "Participants",
        "Quiz_ID = " + str(quiz_id)
    )

    if session['admin'] == 0 and (participant_info is None or not any(user['User_ID'] == session['id'] for user in participant_info)):
        flash("Got FOMO? Join the next one")
        return redirect(url_for('home')) 
    
    else:
        for participant in participant_info:
            participant['Points'] = 0

        all_questions = common_values_not_unique(
            "Question_ID", 
            "Questions",
            "Round_ID",
            "Quiz",
            "Quiz_ID = " + str(quiz_id)
        )

        
        for question in all_questions:
            question_info = get_values(
                "all",
                "SELECT  Answers.User_ID, Answers.Correct, Answers.Timestamp, "
                        "Questions.Question_ID, Questions.Points "
                "FROM    Rounds "
                "INNER JOIN  Quiz "
                "ON Rounds.Quiz_ID = Quiz.Quiz_ID "
                "INNER JOIN  Questions "
                "ON Rounds.Round_ID = Questions.Round_ID "
                "INNER JOIN  Answers "
                "ON Answers.Question_ID = Questions.Question_ID "
                "WHERE Answers.Correct = 1 AND Questions.Question_ID = " + str(question['Question_ID']) + " AND Quiz.Quiz_ID = " + str(quiz_id)
                )
            sorted_question_info = sorted(question_info, key=lambda d: d['Timestamp'])

            question_points = get_values(
                "one",
                "SELECT Points FROM Questions WHERE Question_ID = " + str(question['Question_ID'])
            )

            x = 0
            if int(question_points['Points']) < len(sorted_question_info):
                for x in range(int(question_points['Points'])):
                    for participant in participant_info:
                        if sorted_question_info[x]['User_ID'] == participant['User_ID']:
                            if 'Points' not in participant:
                                participant['Points'] = int(question_points['Points']) - x
                            else:
                                participant['Points'] = int(participant['Points']) + int(question_points['Points']) - x
            else:
                for x in range(len(sorted_question_info)):
                    for participant in participant_info:
                        if sorted_question_info[x]['User_ID'] == participant['User_ID']:
                            if 'Points' not in participant:
                                participant['Points'] = int(question_points['Points']) - x
                            else:
                                participant['Points'] = int(participant['Points']) + int(question_points['Points']) - x

        # Not sure why I need the reverse        
        final_results = sorted(participant_info, key=lambda d: d['Points'], reverse=True)

        for position in range(len(final_results)):
            final_results[position]['Position'] = position+1
            User_Name = get_values(
                "one",
                "SELECT Username FROM Users WHERE User_ID = " + str(final_results[position]['User_ID'])
            )
            final_results[position]['User_Name'] = User_Name['Username']

        return render_template(
            "quiz/results.html",
            name = "Results",
            final_results = final_results,
        )

#######################################################################################################################################################################
# MISC.     ############################################################################
#######################################################################################################################################################################

# This will display the ts&cs page
@app.route('/t&c')
def termsAndConditions():
    # Feeds data into HTML Jinja2 template
    return render_template(
        "misc/t&c.html",
        name="T&Cs"
    )

# This will display the about us page
@app.route('/about')
def about():
    # Feeds data into HTML Jinja2 template
    return render_template(
        "misc/about.html",
        name="About"
    )


#######################################################################################################################################################################
# RUN APP     ###########################################################################
#######################################################################################################################################################################

# This will run the app on the current hardware
if __name__ == "__main__":
    app.run(
        '0.0.0.0',
        debug=True
    )