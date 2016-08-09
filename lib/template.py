import os
import jinja2
# Template
# Sets home path to templates folder
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Points Jinja2 Env to templates directory with XML/HTML Escape
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """ Gets templates and renders with props to environment """
    t = jinja_env.get_template(template)
    return t.render(params)