import dash

# This function is automatically called by C++
def on_command(cmd_text):
    if "help" in cmd_text:
        dash.log("I noticed you are asking for help!")
        dash.log("I am a Python script running inside your C++ shell.")

    if cmd_text == "status":
        dash.log("Plugin seems to operate.")