def login(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input  # UNSAFE
    return execute_query(query)