from http import client
from html.parser import HTMLParser
import urllib
import msvcrt
import json
import hashlib
import os, time

import NgbLogin
import Cipher

# for getting UUID
from subprocess import run, Popen, PIPE
from io import StringIO

class LoginManager:
    def __init__(self):
        # Get the UUID
        cmd_result = run(['wmic', 'csproduct', 'get', 'uuid'], stdout=PIPE)
        cmd_result_str = StringIO(cmd_result.stdout.decode('utf-8'))

        # skip the first line
        cmd_result_str.readline()

        # Grab UUID
        self.uuid = cmd_result_str.readline().strip()
        self.GetLaunchPassport = NgbLogin.GetLaunchPassport
    def Login(self):
        loginFailure = True
        while loginFailure:
            username = input("계정: ")
            password, loginInfoCookies = self.LoadLoginInfoCache(username)
            usedCachedPass = False
            usedCachedCookies = False
            if password == None: # 정보가 없을 때
                password = getpass(prompt = "비밀번호: ", hideChar = '*')
                usedCachedPass = True
            if len(username) > 0 and len(password) > 0:
                if loginInfoCookies == None: # 캐시된 로그인 패스 정보가 없을 때
                    if username.find('@') != -1:
                        LoginMethod = self.NexonLogin
                    else:
                        LoginMethod = self.MabinogiLogin

                    loginInfoCookies, loginFailure = LoginMethod(username, password)
                    if loginFailure:
                        print('계정 또는 비밀번호가 잘못되었습니다.')
                        if usedCachedPass == True:
                            self.DeleteLoginInfoCache(username)
                else:
                    loginFailure = False
                    usedCachedCookies = True
            else:
                print('계정 정보를 정확히 입력해주세요.')
            
        if usedCachedCookies != True:
            self.SaveLoginInfoCache(username, password, loginInfoCookies)
        return loginInfoCookies.get('NPP', ''), NgbLogin.GetLaunchPassport(loginInfoCookies)


    # 전체 넥슨 로그인 처리 과정 실행
    # runs whole Nexon signing-in process
    def NexonLogin(self, username, password):
        encData = NgbLogin.ProcessEncrypt(username, NgbLogin.GetPasswordHash(password), *NgbLogin.GetEncryptInfo())

        headers = {
            'Host': 'login.nexon.com',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://mabinogi.nexon.com/page/main/index.asp'
        }
        body = {
            'strEncData': encData,
            'codeRegSite': 0,
            'strRedirect': 'http%3A%2F%2Fmabinogi.nexon.com%2Fpage%2Fmain%2Findex.asp'
        }

        body_str = urllib.parse.urlencode(body)

        connection = client.HTTPSConnection('login.nexon.com', 443)
        connection.request('POST', '/login/page/loginproc.aspx', body=body_str,
                        headers=headers)

        response = connection.getresponse()
        responseHeaders = response.getheaders()
        loginInfoCookies = NgbLogin.ParseResponseCookies(responseHeaders)

        # 쿠키 내에 NPP와 ENC가 있는지 검증하여 로그인 성공 여부 판별
        # determine if user signed in successfully or not, checking NPP and ENC on cookie
        failure = False
        if not('NPP' in loginInfoCookies and 'ENC' in loginInfoCookies):
            failure = True

        # OTP를 사용하는지 검증하고, OTP를 인증한다.
        # determine if user uses OTP, and authenticate it
        otpCookies = self.CheckOTP(loginInfoCookies)
        
        # OTP 인증이 끝난 이후에 기존 쿠키에 사용자 정보 쿠키를 병합한다.
        # merge user info cookies after OTP authentication
        if otpCookies != None:
            loginInfoCookies.update(otpCookies)
        
        return loginInfoCookies, failure

    def MabinogiLogin(self, username, password):
        
        passwordHash = NgbLogin.GetMabiPasswordHash(password)

        failure = False

        headers = {
            'Host': 'mabinogi.nexon.com',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://mabinogi.nexon.com/page/main/index.asp'
        }
        body = {
            'user_id': username,
            'user_pwd': passwordHash,
            'PageLocation': 'http://mabinogi.nexon.com/page/main/index.asp'
        }

        body_str = urllib.parse.urlencode(body)

        connection = client.HTTPSConnection('mabinogi.nexon.com', 443)
        connection.request('POST', '/page/common/login/_logincheck_com2.asp', body=body_str,
                        headers=headers)

        response = connection.getresponse()
        responseHeaders = response.getheaders()
        responseBody = response.read()
        loginInfoCookies = NgbLogin.ParseResponseCookies(responseHeaders)


        if responseBody.find(b'login_security.asp') != -1:
            print("계정의 로그인 시도에 10회 이상 실패했습니다.")
            print("공식 홈페이지에서 정상 로그인 후 시도해주세요.")
            failure = True

        # OTP를 사용하는지 검증하고, OTP를 인증한다.
        # determine if user uses OTP, and authenticate it
        otpCookies = self.CheckOTP(loginInfoCookies, responseBody)

        # OTP 인증이 끝난 이후에 기존 쿠키에 사용자 정보 쿠키를 병합한다.
        # merge user info cookies after OTP authentication
        if otpCookies != None:
            loginInfoCookies.update(otpCookies)

        # 쿠키 내에 nexonid가 있는지 검증하여 로그인 성공 여부 판별
        # 마비노기 계정에는 NPP와 ENC없이 게임 유저 정보쿠키를 통해 받아내는 passport만으로 게임 접속이 가능하다.
        # determine if user signed in successfully or not, checking nexonid on cookie
        # Mabinogi Acc. don't use NPP and ENC cookie during the launching process
        # so we can get passport with user game info cookies..
        # 따라서 유저 정보를 정상적으로 받았는지 체크하는 과정으로 로그인 성공 여부 판별이 가능하다.
        # we need to check if we received user game info successfully or not.
        if not('nexonid' in loginInfoCookies):
            failure = True

        # NPP 키가 없으면 이후에 에러가 날 것이므로(kanan.py에서 로그인 정보 쿠키의 NPP키를 참조하기 때문)
        # 없는 값이라도 정보에 추가하여 오류를 방지
        # it'll be error when NPP value doesn't exist, so append it as an empty value
        if not('NPP' in loginInfoCookies):
            loginInfoCookies['NPP'] = ''
        
        return loginInfoCookies, failure

    def CheckOTP(self, loginInfoCookies, responseBody=None): 
        loginCookieString = NgbLogin.MakeCookieString(loginInfoCookies)

        if responseBody == None:
            headers = {
                'Host': 'mabinogi.nexon.com',
                'Referer': 'http://mabinogi.nexon.com/page/main/index.asp',
                'Cookie': loginCookieString
            }

            connection = client.HTTPConnection('mabinogi.nexon.com')
            connection.request('POST', '/page/main/index.asp', headers=headers)

            response = connection.getresponse()
            responseBody = response.read()
            responseHeaders = response.getheaders()
            cookies = NgbLogin.ParseResponseCookies(responseHeaders)
        else:
            cookies = loginInfoCookies

        if 'RQOTP' in cookies and cookies['RQOTP'] != '':
            # 요청 헤더에 이 쿠키가 없으면 서버에서 OTP 인증 요청인지 모름.
            # the Nexon server's not gonna know whether it's OTP auth request, when we don't put this.
            RQOTP = cookies['RQOTP']

            class OTPHTMLParser(HTMLParser):
                formBody = {}
                def handle_starttag(self, tag, attrs):
                    if tag == 'input':
                        attr = dict(attrs)
                        if attr['type'] == 'hidden':						
                            self.formBody[attr['name']] = attr['value']

            parser = OTPHTMLParser()
            #'<nxaml><object name="result"><string name="e" value="010001" /><string name="m" value="A3A69317FB92A534912A0999A7EEE826358C05F434C5E1EDB61C68E882CE52F7573FA44CE46E858673A8A328E17712FDAAECF383F13ECC1FD9D1505D2F23C983AD36F951788DEE30F1AE2A34F2DB13E46C409980A5467E05C7667AAD896464ABB073AA01AAFE130E28FA4D3D6A57ECA8422A482E22C5E0BA67434160B95A68DF" /><string name="h" value="k4efXXPgsbEQd3vqDlvI1vYBwMk=" /></object></nxaml>'
            parser.feed(responseBody.decode('utf-8'))

            headers = {
                'Host': 'mabinogi.nexon.com',
                'Referer': 'http://mabinogi.nexon.com/page/member/login_otp.asp',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': loginCookieString+'; RQOTP='+RQOTP
            }

            if 'usr_id' in parser.formBody:
                # usr_id는 웹 서버 상에서 잘못 들어온 쿠키 값이고, 이를 user_id로 바꿔서 적용한다.
                # usr_id cookie which named wrong should be renamed as user_id
                parser.formBody['user_id'] = parser.formBody['usr_id']
                del parser.formBody['usr_id']

            otpFailure = True
            import re
            p = re.compile(r'^\d{7}$')
            
            # OTP 인증이 성공할 때 까지 반복문 실행
            # do loop til we get authed successfully
            while otpFailure:
                otpPW = input("OTP 인증번호: ")
                # 사전 검증
                # verification
                if p.match(otpPW) == None:
                    print('OTP 형식이 잘못되었습니다.')
                    continue
                
                parser.formBody['OTP_PW'] = otpPW
                
                formBodyString = urllib.parse.urlencode(parser.formBody)
                connection = client.HTTPConnection('mabinogi.nexon.com')
                connection.request('POST', '/page/main/index.asp', headers=headers, body=formBodyString)

                response = connection.getresponse()
                responseHeaders = response.getheaders()
                cookies = NgbLogin.ParseResponseCookies(responseHeaders)
                
                if not('nexonid' in cookies):
                    otpFailure = True
                    print('OTP가 틀렸습니다.')
                else:
                    otpFailure = False

            return cookies
        return None

    # 비밀번호 정보만 있다면 (password, None) | 패스포트 캐시까지 있다면 (password, loginInfo)
    # 찾을 수 없다면 (None, None)
    def LoadLoginInfoCache(self, username, encoding='utf-8'):
        infoCipher = Cipher.AESCipher(self.uuid)
        if not os.path.exists('cache/'+self.uuid):
            return None, None

        with open('cache/'+self.uuid, 'r') as loginInfoFile:
            data = loginInfoFile.read()
            if len(data) < 1:
                return None, None
            loginInfos = json.loads(data)
            userPassEnc = loginInfos.get(username, None)
            if userPassEnc == None:
                return None, None
            password = infoCipher.decrypt(userPassEnc)
        
        cacheCypher = Cipher.AESCipher(userPassEnc)
        h = hashlib.md5()
        h.update(username.encode('utf-8')) #update 안에는 인코딩할 문자열을 집어넣습니다.
        usernameEnc = h.hexdigest() #hexdigest는 우리가 익히 아는 16진수로 출력.
        
        if not os.path.exists('cache/'+usernameEnc):
            return password, None

        with open('cache/'+usernameEnc, 'r', encoding='utf-8') as loginInfoCacheFile:
            data = loginInfoCacheFile.read()
            if len(data) < 1:
                return password, None
            cacheDec = cacheCypher.decrypt(data)
            loginInfo = json.loads(cacheDec)
            cachedAt = loginInfo.get('cachedAt')
            if time.time() - cachedAt <= 600: # 10 * 60, 10분
                return password, loginInfo
            else:
                return password, None # 만료되었을 것이므로 None 처리...
    
    def SaveLoginInfoCache(self, username, password, loginInfo):
        infoCipher = Cipher.AESCipher(self.uuid)
        passEnc = infoCipher.encrypt(password)
        cacheCypher = Cipher.AESCipher(passEnc.decode('utf-8'))
        with open('cache/'+self.uuid, 'r', encoding='utf-8') as loginInfoFile:
            data = loginInfoFile.read()
        with open('cache/'+self.uuid, 'w', encoding='utf-8') as loginInfoFile:
            if len(data) < 1:
                data = '{}'
            loginInfos = json.loads(data)
            loginInfos[username] = passEnc.decode('utf-8')
            json.dump(loginInfos, loginInfoFile)

        h = hashlib.md5()
        h.update(username.encode('utf-8')) #update 안에는 인코딩할 문자열을 집어넣습니다.
        usernameEnc = h.hexdigest() #hexdigest는 우리가 익히 아는 16진수로 출력.
        
        #datetime.fromtimestamp(loginInfo['cachedAt'])
        with open('cache/'+usernameEnc, 'w', encoding='utf-8') as loginInfoCacheFile:
            loginInfo['cachedAt'] = time.time()
            cacheEnc = cacheCypher.encrypt(json.dumps(loginInfo))
            loginInfoCacheFile.write(cacheEnc.decode('utf-8'))

    def DeleteLoginInfoCache(self, username):
        if not os.path.exists('cache/'+self.uuid, 'w'):
            return
        with open('cache/'+self.uuid, 'r') as loginInfoFile:
            data = loginInfoFile.read()
        with open('cache/'+self.uuid, 'w') as loginInfoFile:
            if len(data) < 1:
                return
            loginInfos = json.loads(data)
            userPassEnc = loginInfos.pop(username, None)
            if userPassEnc == None:
                return
            json.dump(loginInfos, loginInfoFile)

        h = hashlib.md5()
        h.update(username.encode('utf-8')) #update 안에는 인코딩할 문자열을 집어넣습니다.
        usernameEnc = h.hexdigest() #hexdigest는 우리가 익히 아는 16진수로 출력.
        if os.path.exists('cache/'+usernameEnc):
            os.remove('cache/'+usernameEnc)
    
        

def getpass(prompt = 'Password: ', hideChar = ' '):

	count = 0
	password = ''

	for char in prompt:
		msvcrt.putwch(char) # cuz password, be trouble
		
	while True:
		char = msvcrt.getwch()
		
		if char == '\r' or char == '\n':
			break
		
		if char == '\003':
			raise KeyboardInterrupt # ctrl + c

		if char == '\b':
			count -= 1
			password = password[:-1]

			if count >= 0:
				msvcrt.putch(b'\b')
				msvcrt.putch(b' ')
				msvcrt.putch(b'\b')
			
		else:
			if count < 0:
				count = 0
				
			count += 1
			password += char
			msvcrt.putwch(hideChar)
			
	msvcrt.putch(b'\r')
	msvcrt.putch(b'\n')

	return "%s" % password if password != '' else ""
