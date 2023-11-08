import paho.mqtt.client as mqtt
import json
import re
from util import encryption, decryption, getPacket, getRSAKey
import time

last_time_stamp = int(time.time())

rec_topic = ''
rec_string = ''
device_name = 'kettle'
re_message = ''
user_list = ['user1']
public_key = {}
private_key = {}

model = 'cold'
temperature = 24
state = 'off'


# todo:解密

def proc_message(s ,res):
    global public_key, private_key, device_name, last_time_stamp
    rec_data = json.loads(s)
    des_device = rec_data['des']
    # print('ddd'+res)
    if des_device == device_name:
        if rec_data['encry_key'] == '':
            public_key[res] = rec_data['encry_text']

            # print(public_key[res])

            private_key[res], pub = getRSAKey()
            s = getPacket(res, pub)
            # print(pub)
            client.publish(device_name, s)
            return
        else :
            # print(private_key[res])
            
            rec_message, ex_timestamp = decryption(rec_data['encry_key'], rec_data['encry_text'], private_key[res])
            if ex_timestamp < last_time_stamp:
                print('消息过期')
                return
            last_time_stamp = ex_timestamp
    else:
        return
    message_handle(rec_message ,res)
    return

def send_state(res):
    global state, model, temperature, device_name
    d = {
        'state': state,
        'model': model,
        'temperature': temperature
    }
    s = getPacket(res, json.dumps(d), public_key[res])
    client.publish(topic=device_name, payload=s, qos=0, retain=False)

# todo:处理消息
def message_handle(s, res):
    global state, model, temperature
    # print('here'+s)
    if(s!='on' and state =='off'):
        return
    if s == 'on':
        state = 'on'
    elif s == 'off':
        state = 'off'
    elif s == 'warm':
        model = 'warm'
        temperature = 95
    elif s == 'keep':
        model = 'keep'
        temperature = 50
    # elif re.match(r'set \d+', s):
    #     match = re.match(r'set (\d+)', s)
    #     temperature = int(match.group(1))
    elif s == 'get':
        send_state(res)

    if temperature > 30:
        temperature = 30
    elif temperature < 16:
        temperature = 16


def on_connect(client, userdata, flags, rc):
    print("Connected with result code: " + str(rc))


def on_message(client, userdata, msg):
    # print(msg.topic + ": " + msg.payload.decode('utf-8'))
    global user_list
    if(msg.topic in user_list):
        #print('zheli ')
        proc_message(msg.payload.decode('utf-8') , msg.topic)


#   订阅回调
def on_subscribe(client, userdata, mid, granted_qos):
    print("On Subscribed: qos = %d" % granted_qos)
    pass


#   取消订阅回调
def on_unsubscribe(client, userdata, mid):
    print("On unSubscribed: qos = %d" % mid)
    pass


#   发布消息回调
def on_publish(client, userdata, mid):
    print("On onPublish: qos = %d" % mid)
    pass


#   断开链接回调
def on_disconnect(client, userdata, rc):
    print("Unexpected disconnection rc = " + str(rc))
    pass


client = mqtt.Client(device_name)
client.username_pw_set(device_name, '123456')
client.on_connect = on_connect
client.on_message = on_message
client.on_publish = on_publish
client.on_disconnect = on_disconnect
client.on_unsubscribe = on_unsubscribe
client.on_subscribe = on_subscribe

client.connect('8.140.62.20', 1883, 600)
print(1)
# 600为keepalive的时间间隔
client.subscribe('user1', qos=0)
client.loop_forever()  # 保持连接