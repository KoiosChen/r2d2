from flask import redirect, session, url_for, render_template, flash, request, jsonify, send_from_directory
from flask_login import login_required
from ..models import *
from ..decorators import permission_required
from .. import db, logger, scheduler
from .forms import PostForm, DeviceForm, RegistrationForm, AreaConfigForm, UserModal, AreaModal
from . import main
import time
from ..MyModule import OperateDutyArrange
from ..MyModule.GetConfig import get_config
from ..MyModule.UploadFile import uploadfile
from ..MyModule.SeqPickle import get_pubkey, update_crypted_licence
from werkzeug.utils import secure_filename
import json
from bs4 import BeautifulSoup
import datetime
import os
import re
import requests
from sqlalchemy import or_, and_


@main.route('/echarts_1', methods=['GET'])
def echarts_1():
    return render_template('echart_1.html')