from http import client
from base64 import b64encode
import hashlib
from html.parser import HTMLParser
import urllib

#############################################################################
########################### 패스워드 해쉬 얻어내기 ############################
#############################################################################

class PasswordHashHTMLParser(HTMLParser):
	PasswordHashKeyString = None
	def handle_starttag(self, tag, attrs):
		if tag == 'string':
			attr = dict(attrs)
			if attr['name'] == 'PasswordHashKeyString':
				self.PasswordHashKeyString = attr['value']

def GetPasswordHash(password):
	# 해쉬를 얻기위해 주소에 접근 및 응답 정보 파싱
	connection = client.HTTPSConnection('sso.nexon.com', 443)
	connection.request('GET', '/Ajax/Default.aspx?_vb=GetPasswordHashKey')
	response = connection.getresponse().read().decode('utf-8').split("'")[1]

	parser = PasswordHashHTMLParser()
	# '<nxaml><number name="_cs" value="10738472"/><object name="_state" type="State"></object><string name="PasswordHashKeyString" value="auth:1:4711290:12270887558120760867"/></nxaml>'
	parser.feed(response)

	#response = loads(connection.getresponse().read().decode('utf-8'))

	hashString = parser.PasswordHashKeyString.split(":")

	header =hashString[0] + ':' + hashString[1] + ':' + hashString[2] + ':' # auth:1:4697659:
	hashKey = hashString[3] # 15099027238648856955

	# 4E 65 78 6F 6E 55 73 65 72 (넥슨의 로그인 처리 스크립트 상에서 사용되는 값) => NexonUser
	# 16진수로 NexonUser 를 나타낸 것이다.
	# Cryptodome을 이용한 표준 HMAC SHA256 로는 다른 결과값이 나오는 것을 확인.
	# 넥슨에서 사용하는 NgbHash를 python 코드로 구현해서 사용하거나, hmac 모듈을 통해 구현
	#from NgbHash import NgbHash
	#NgbHashObject = NgbHash()
	#passwordHash = header + NgbHashObject.HMAC_SHA256_MAC(key=hashKey, msg=NgbHashObject.HMAC_SHA256_MAC(key="NexonUser", msg=password))
	import hmac
	dig = hmac.new(b'NexonUser', msg=password.encode(), digestmod=hashlib.sha256).hexdigest().upper()
	passwordHash = header + hmac.new(hashKey.encode(), msg=dig.encode(), digestmod=hashlib.sha256).hexdigest().upper()
	
	return passwordHash
#############################################################################
############################## encData 얻어내기 ##############################
#############################################################################	

class EncryptInfoHTMLParser(HTMLParser):
	encryptionExponent = None
	modulus = None
	hashValue = None
	def handle_starttag(self, tag, attrs):
		if tag == 'string':
			attr = dict(attrs)
			if attr['name'] == 'e':
				self.encryptionExponent = attr['value']
			elif attr['name'] == 'm':
				self.modulus = attr['value']
			elif attr['name'] == 'h':
				self.hashValue = attr['value']
		
# 암호화 정보를 얻기위해 주소에 접근 및 응답 정보 파싱
# Sends request to Nexon page, for getting encrypt info, and parses the response.
def GetEncryptInfo():
	connection = client.HTTPSConnection('login.nexon.com', 443)
	connection.request('GET', '/login/page/encryptinfo.aspx')
	response = connection.getresponse().read().decode('utf-8').split("'")[1]

	parser = EncryptInfoHTMLParser()
	#'<nxaml><object name="result"><string name="e" value="010001" /><string name="m" value="A3A69317FB92A534912A0999A7EEE826358C05F434C5E1EDB61C68E882CE52F7573FA44CE46E858673A8A328E17712FDAAECF383F13ECC1FD9D1505D2F23C983AD36F951788DEE30F1AE2A34F2DB13E46C409980A5467E05C7667AAD896464ABB073AA01AAFE130E28FA4D3D6A57ECA8422A482E22C5E0BA67434160B95A68DF" /><string name="h" value="k4efXXPgsbEQd3vqDlvI1vYBwMk=" /></object></nxaml>'
	parser.feed(response)

	return (parser.encryptionExponent, parser.modulus, parser.hashValue)

def ProcessEncrypt(username, passwordHash, encryptionExponent, modulus, hashValue):

	key = {}
	key['e'] = int(encryptionExponent, 16)
	key['m'] = int(modulus, 16)
	key['digitSize'] = int((2*((len(modulus)/4)-1))+2)
	key['chunkSize'] = key['digitSize'] - 11
	key['radix'] = 16

	# (len(modulus)/4)-1 이걸로 biHighIndex를 대체할 수 있는 듯하다.
	# it seems like biHighIndex can be replaced with (len(modulus)/4)-1
	authHash = [username, passwordHash]
	authData = ''
	
	if passwordHash != None:
		authData = hashValue + '\\'
	
	for i in range(len(authHash)):
		authData += b64encode( authHash[ i ].encode() )[:].decode() # base64로 인코딩하는데, 인수를 byte로 보내고, 받을때 byte를 string으로 바꾼 후 맨 뒤에 붙는 \n를 제거
		
		if i < len(authHash)-1:
			authData += '\\'
	
	# 결국 authData는 encryptInfo에서 받아온 hash값 + username의 base64인코드된 값 + passwordHash의 base64인코드된 값이다.
	# 이를 키를 이용해서 암호화한 것이 encData가 된다.
	# Eventually, authData = (hash data returned from GetEncryptInfo()) +'\\'+ (base64 encoded username) +'\\'+ (base64 encoded passwordHash)
	# the result value after encrypting this, that's encData. 
	val = EncryptString( key, authData )
	return val

def EncryptString( key, s ):	
	a = []
	sl = len(s)
	
	for i in range(sl):
		a.append(ord(s[i])) # charCode를 구한다
		i += 1
	
	import random

	al = len(a) # a의 길이
	result = '' # 결과 초기화
	k = None
	i = 0
	while i < al:
		if ( i + key['chunkSize'] ) > al:
			msgLength = int(al % key['chunkSize'])
			b = (key['digitSize'])*[0]
		else:
			msgLength = int(key['chunkSize'])
			b = (msgLength*2+1)*[0]
		#msgLength = int(al % key['chunkSize'] if ( i + key['chunkSize'] ) > al else key['chunkSize'])
		#b = (key['chunkSize']*2+1)*[0]
		for x in range(msgLength):
			b[x] = (a[ i + msgLength - 1 - x ])
		
		b[ msgLength ] = 0
		paddedSize = max( 8, key['digitSize'] - 3 - msgLength )

		for x in range(paddedSize):
			b[ msgLength + 1 + x ] = random.randrange(1,254)

		b[ key['digitSize'] - 2 ] = 2
		b[ key['digitSize'] - 1 ] = 0

		
		'''
		block = key['digitSize']*[0]
		k = 0
		while k < key['digitSize']:
			# BigInt.js의 한 디짓은 65535를 담을 수 있다. 즉, 한 배열 칸에 8비트 수용 가능
			block[ j ] = b[ k ]
			blockint += b[ k ] << (k*8)
			k += 1
			block[ j ] += b[ k ] << 8
			blockint += b[ k ] << (k*8)
			k += 1
			j += 1
		'''
		# 자바스크립트 코드에서의 block은 BigInt.js 라이브러리 타입으로 큰 정수 데이터를 저장,
		# 파이썬에서 이를 long 타입을 통해 감당할 수 있으므로, 하나의 변수에 모두 몰아담는다.
		block = 0
		for k in range(len(b)):
			block += b[ k ] << (k*8)

		# 기존 코드에서 BarrettMu_powMod 실행부, power연산을 실행한다.
		# originally, it is BarrettMu_powMod. we can do that with powering.
		crypt = pow(block, key['e'], key['m'])
		text = ''.join(format(crypt, '04x')).zfill(256) # padding이 안되는경우가 있어 zfill로 256길이를 확실히 해 준다 (zerofill 256 to pad zeros)
		result += text + ' '
		i += key['chunkSize']
	
	return result[:-1]

# 헤더에서 Set-Cookie 정보들을 파싱하는 과정
# parses Set-Cookie header
def ParseResponseCookies(responseHeaders):
	result = {}
	
	for (k, v) in responseHeaders:
		if(k == 'Set-Cookie'):
			cookieData = v.split(';')
			for cookie in cookieData:
				cvCookie = cookie.split('=', 1) # 두 개의 값만 나와야 한다, 두번째 인수에 최대 인덱스가 될 1 을 넣어줘야 한다.
				if len(cvCookie) < 2:
					cvCookie.append('')
				cookieKey, cookieValue = cvCookie
				result[cookieKey] = cookieValue
	
	return result

# 파싱된 쿠키 정보를 다시 하나의 스트링으로 묶는 과정
# joins parsed cookies in dict as string type
def MakeCookieString(cookies):
	return "; ".join([str(x)+"="+str(y) for x,y in cookies.items()])

# 게임 실행에 필요한 패스포트값을 얻어내는 과정
# gets passports value needed to run game process.
def GetLaunchPassport(loginInfoCookies):
	
	loginCookieString = MakeCookieString(loginInfoCookies)

	headers = {
		'Host': 'mabinogi.nexon.com',
		'Referer': 'http://mabinogi.nexon.com/page/main/index.asp',
		'Cookie': loginCookieString
	}

	connection = client.HTTPConnection('mabinogi.nexon.com')
	connection.request('POST', '/page/common/gamestart.asp', headers=headers)

	response = connection.getresponse()
	responseHeaders = response.getheaders()
	responseBody = response.read()
	launchCookies = ParseResponseCookies(responseHeaders)

	# OTP 사용중이지 않은 넥슨계정은 두 번의 게임 접속 요청 절차가 필요하다.
	# nexonid가 쿠키에 있다는 것은 요청을 한 번 더 보내서 passport를 받아내야 한다는 뜻.
	# (passport를 받아내기 위해서는 마비노기 게임 정보가 필요한데, 이 정보를 받아내는 것이 1차)
	# (받아낸 정보로 passport를 요청하는것이 2차이다, OTP를 사용하는 넥슨계정 또는 마비노기 계정은)
	# (로그인하면 알아서 게임 유저 정보를 쿠키로 넘겨주므로 한 번의 요청으로도 끝낼 수 있다)
	# Nexon accounts which don't use OTP need to request passport twice.
	# cuz Nexon accounts using OTP and Mabinogi accounts would receive user infos as cookies when user sign in,
	# but Nexon accs not using OTP only receive NPP and ENC, we can get user info by requesting launch url with NPP and ENC cookies
	# when we get user info, we need to request actual launch process.
	if 'nexonid' in launchCookies:
		headers['Cookie'] += '; ' + MakeCookieString(launchCookies)
		connection = client.HTTPConnection('mabinogi.nexon.com')
		connection.request('POST', '/page/common/gamestart.asp', headers=headers)

		response = connection.getresponse()
		responseBody = response.read()

	passport = responseBody.decode()
	return passport


def GetMabiPasswordHash(password):
	m = hashlib.md5()
	m.update(password.encode())
	s = hashlib.sha256()
	s.update(m.hexdigest().upper().encode('utf-8'))
	return s.hexdigest().upper()
'''
로그인 과정


https://sso.nexon.com/Ajax/Default.aspx?_vb=GetPasswordHashKey 에 접근해 패스워드를 해싱할 키를 요구하면
<nxaml><number name="_cs" value="10738472"/><object name="_state" type="State"></object><string name="PasswordHashKeyString" value="auth:1:4711290:12270887558120760867"/></nxaml>
와 같은 데이터를 넘겨준다.

여기서 PasswordHashKeyString 인 auth:1:4711290:12270887558120760867 를

각각

auth:1:4711290: 와 (패스워드 해시의 헤더이다, 이하 header)

12270887558120760867 로 (패스워드 해시의 해싱 키이다, 이하 hashKey) 분리하고,

실제 패스워드를 "NexonUser" 라는 키를 이용해 HMAC_SHA256으로 암호화한 값을,

hashKey 를 이용해 한 번 더 HMAC_SHA256 암호화한 값이 패스워드 해시이다... 즉,

passwordHash = header + NgbHashObject.HMAC_SHA256_MAC(key=hashKey, msg=NgbHashObject.HMAC_SHA256_MAC(key="NexonUser", msg=password))

패스워드 해시를 얻어냈다면,

https://login.nexon.com/login/page/encryptinfo.aspx 에 요청을 하면 

<nxaml><object name="result"><string name="e" value="010001" /><string name="m" value="A3A96317FB92A534912A0999A7EEE826358C05F434C5E1EDB61C68E882CE52F7573FA44CE46E858673A8A328E17712FFAAECF323F13ECC1FA9D150FD2F23D983FD36F951788DEE30F2AE2A34F2DB13E46C409980A5467E05C7667AAD896464ABB073AA01AAFE130E28FA4D3D6A57ECA8422A482E22C5E0BA67434160B95A67DF" /><string name="h" value="w0schATa6RV2oz6OXM2n9IV1oA0=" /></object></nxaml>

와 같은 정보를 준다.

(이하 e와 m, 그리고 h를, 각각 encryptionExponent, modulus, hashValue로 칭한다.)

실제 username 값과, 위에서 구한 passwordHash를 순서대로 base64로 인코딩하여
hashValue에 \ 를 구분자로 하여 이어붙인... 즉,

authData += hashValue + '\\' + (base64로 인코딩된 username) + '\\' + (base64로 인코딩된 passwordHash)

인 hashValue를 EncryptString 함수에서 연산의 s(string)값으로 이용한다.

# EncryptString은 키와 문자열을 받아, 문자열을 블록단위로 묶은 후 이를 정수화하고, pow(blockint, key['e'], key['m']) 연산을 수행하는 함수이다.
EncryptString( key, authData )

결과가 될 encData는 256자리로 암호화된 정보들이 공백을 구분자로 하여 붙어있는 형태이다.
result(encData가 될 데이터) = 2ae4a593c89c77041874b58911b71d8f859b96bc2ef3ff1f196d8623389d4c4113a4877f7fcba2af175fc593b312af0488702b6af3ccfd5cb465b10fabc988a2736b20d10455dfb6a5b9803acee1185f657cbd64964d4e9a518e8120cf7ac81c120b23df6ae460fcb5b9752427baa7cd214aaf1b28062c76f2c382744aec71ad 4035659ca794cfb6e285e3302e77f6c815c752daae12cbc445f6f821baac4805d575d82e76efa8be54c9bff8d2ee4a38e6c8dcadcaf7f981a62f9ca16f26a92a4e31edafe3310f9c634e72f366a2a1a620908a951f9a62cc22128239c6c760a8810ea499490c4930824c4e0d4a7d1611206e50987c5093dfff950b06cac8b321


이 정보를 이용해

https://login.nexon.com/login/page/loginproc.aspx 에 encData를 strEncData라는 이름으로 바디에 실어 POST 요청, 서버에서 검증 후 쿠키 형식으로 로그인 정보를 보내준다.
'''
