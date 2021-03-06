#######################################################################################################################################################################
# PACKAGES
#######################################################################################################################################################################
# This section imports different packages required for the functions to work

from data import info
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from MySQLdb.cursors import DictCursor
import os
import re
import time
from werkzeug.security import generate_password_hash, check_password_hash


######################################################################################################################################################################
# MYSQL SETUP
######################################################################################################################################################################
# This section sets up the connection between the app and the mysql database hosted on a public cloud

# __name__ is for best practice
app = Flask(__name__) 

# Enter your database connection details below
app.config["MYSQL_DB"] = info.MySQLdb
app.config["MYSQL_HOST"] = info.MySQLhost
app.config["MYSQL_PASSWORD"] = info.MySQLpassword
app.config["MYSQL_USER"] = info.MySQLuser

# Change this to your secret key (can be anything, it's for extra protection)
# This was to get flask flash to work
app.config['SECRET_KEY'] = 'something only you know' 


# Initialise MySQL
mysql = MySQL(app)


######################################################################################################################################################################
# FUNCTIONS
######################################################################################################################################################################
# These functions are independent 

# This functions checks if two values are identical
def duplicate(value1,value2):
    if value1 == value2:
        return True
    else:
        return False

# This function checks if a string contains an @ symbol.
# I use the @ symbol as an unique characteristic of email addresses, so this can be used to determine if a string is an email address
def email(string):
    return re.search("@", string)

# This function returns the current time and date
def timestamp():
    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return timestamp


######################################################################################################################################################################
# SESSION
######################################################################################################################################################################
# These functions use the session feature of flask

# This function checks to see if the user currently logged in is an admin
def authorisation():
    if session['admin'] == 0:
        flash("You do not have the required authorisation")
        return True
    else:
        return False

# This function logs a user into the lession
def login_session(id, username, email, admin):
    session['loggedin'] = True
    session['id'] = id
    session['username'] = username
    session['email'] = email
    session['admin'] = admin

# This function logs a user out of the lession
def logout_session(): # clears all session information
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('email', None)  
    session.pop('admin', None) 


######################################################################################################################################################################
# QUIZ
######################################################################################################################################################################
# These functions are specific to the Quiz



######################################################################################################################################################################
# MYSQL
######################################################################################################################################################################
# These functions perform different mySQL queries

# This function checks if a value is in the database and returns True or False
def check_db(output, table, conditions):
    cur = mysql.connection.cursor()
    cur.execute("SELECT %s FROM %s WHERE %s" % (output, table, conditions))
    mysql.connection.commit()
    output = cur.fetchone()
    cur.close()    
    if output:
        return True
    else:
        return False

# This function selects common values between two tables
def common_values(output, table1, table2, table1_column_name, table2_column_name):
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s INNER JOIN %s ON %s = %s" % (output, table1, table2, table1_column_name, table2_column_name))
    mysql.connection.commit()    
    data = cur.fetchall()
    cur.close()   
    return data

# This function selects common values between two tables
def common_values_not_unique(output, table1, common_column, table2, conditions): 
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s)" % (output, table1, common_column, common_column, table2, conditions))
    mysql.connection.commit()    
    data = cur.fetchall()
    cur.close()   
    return data

# This function only one common value between two tables
def common_value_not_unique(output, table1, common_column, table2, conditions): 
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s)" % (output, table1, common_column, common_column, table2, conditions))
    mysql.connection.commit()    
    data = cur.fetchone()
    cur.close()   
    return data

# This function selects entries from table1 that aren't in table 2
def compare_two_tables(output, table1, common_column, table2, conditions): 
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s WHERE %s NOT IN (SELECT %s FROM %s WHERE %s)" % (output, table1, common_column, common_column, table2, conditions))
    mysql.connection.commit()    
    data = cur.fetchall() #built in function to return a tuple, list or dictionary
    cur.close()   
    return data

# This function deletes a table entry based on a condition
def delete_db_entry(table, conditions):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM %s WHERE %s" % (table, conditions))
    mysql.connection.commit()
    cur.close()

# This function returns outputs from a table based on the value.
def get_entries_fromDB(output, table, conditions): 
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s WHERE %s" % (output, table, conditions))
    mysql.connection.commit()
    data = cur.fetchall() #built in function to return a tuple, list or dictiona
    cur.close()   
    return data # returns as a dict

# This function returns a single output from a table based on the value.
def get_entry_fromDB(output, table, conditions):
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT %s FROM %s WHERE %s" % (output, table, conditions))
    mysql.connection.commit()
    data = cur.fetchone() #built in function to return a tuple, list or dictionary
    cur.close()   
    return data # returns as a dict

# This function returns one or all the values based on a query
def get_values(amount, query):
    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute(query) # Query must already be in a string format
    mysql.connection.commit()
    if amount == "all":    
        data = cur.fetchall() #built in function to return a tuple, list or dictionary
    else:
        data = cur.fetchone() #built in function to return a tuple, list or dictionary
    cur.close() 
    return data

# This function will insert a value into a database
def insert_db_entry(table, columns, values):
    cur = mysql.connection.cursor()
    cur.execute("INSERT IGNORE INTO %s (%s) VALUES (%s)" % (table, columns, values))
    mysql.connection.commit()
    cur.close()

# This function will update a value in a table
# Initially was a list for updates and conditions, but string more efficient as no minipulation required
def update_db_entry(table, updates, conditions): 
    cur = mysql.connection.cursor()
    cur.execute("UPDATE %s SET %s WHERE %s" % (table, updates, conditions))
    mysql.connection.commit()
    cur.close() 