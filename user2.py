import paho.mqtt.client as mqtt
import time
import json
from util import encryption, decryption, getPacket, getRSAKey
import time

last_time_stamp = int(time.time())

def proc_message(data):
    global cur_device, private_key, public_key, last_time_stamp
    # print(private_key)
    message, ex_timestamp = decryption(data['encry_key'], data['encry_text'], private_key)
    if ex_timestamp < last_time_stamp:
        print('消息过期')
        return
    last_time_stamp = ex_timestamp
    print(message)


def on_connect(client, userdata, flags, rc):
    print("Connected with result code: " + str(rc))


def on_message(client, userdata, msg):
    global cur_device, private_key, public_key
    if(msg.topic != cur_device): return

    rec_data = json.loads(msg.payload.decode('utf-8'))
    if(rec_data['des'] != 'user2'): return
    if rec_data['encry_key'] == '':
        public_key = rec_data['encry_text']
        # print(public_key)
        return
    else:
        proc_message(rec_data)


#   订阅回调
def on_subscribe(client, userdata, mid, granted_qos):
    # print("On Subscribed: qos = %d" % granted_qos)
    pass


#   取消订阅回调
def on_unsubscribe(client, userdata, mid, granted_qos):
    print("On unSubscribed: qos = %d" % granted_qos)
    pass


#   发布消息回调
def on_publish(client, userdata, mid):
    # print("On onPublish: mid = %d" % mid)
    pass


#   断开链接回调
def on_disconnect(client, userdata, rc):
    print("Unexpected disconnection rc = " + str(rc))
    pass

client = mqtt.Client('user2')
client.username_pw_set('user2', '123456')
client.on_connect = on_connect
client.on_message = on_message
client.on_publish = on_publish
client.on_disconnect = on_disconnect
client.on_unsubscribe = on_unsubscribe
client.on_subscribe = on_subscribe
client.connect('8.140.62.20', 1883, 600)  # 600为keepalive的时间间隔

client.subscribe('device1', qos=0)
# client.subscribe('device2', qos=0)
client.loop_start()

device_list = ['air_condition', 'lamp']
help_string = '1. 测试\n2. 测试\nquit: 退出'
inst_list = []

public_key = ''
private_key = ''
cur_device = ''

while True:
    while True:
        des_device = input("请输入目标设备(输入all-device查看当前所有设备):")
        if des_device == 'all-device':
            print(device_list)
            continue
        elif des_device in device_list:
            private_key, pub= getRSAKey()
    
            cur_device = des_device
            client.subscribe(des_device, qos=0)
            s = getPacket(des_device, pub,'')
            client.publish(topic='user2', payload=s, qos=0, retain=False)
            time.sleep(2)
            break
        else:
            print("设备不存在，请重新输入")
            continue

    while True:
        # print(public_key)
        message = input("请输入指令(输入help获取帮助):")
        if message == 'help':
            print(help_string)
        elif message == 'quit':
            break
        else:
            send_pack = getPacket(des_device, message, public_key)
            # print('daodao')
            client.publish(topic='user2', payload=send_pack, qos=0, retain=False)
            time.sleep(2)


