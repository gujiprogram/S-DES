# This Python file uses the following encoding: utf-8
import os
from pathlib import Path
import sys
from PySide2.QtWidgets import QApplication, QWidget, QPushButton,QStackedWidget,QLineEdit,QTextEdit
from PySide2.QtGui import QPixmap, QPalette, QBrush
from PySide2.QtCore import QFile
from PySide2.QtUiTools import QUiLoader
import binascii
import threading
import time

P10_table = [3,5,2,7,4,10,1,9,8,6]
P8_table = [6,3,7,4,8,5,10,9]
Leftshift_table_1 = [2,3,4,5,1]
Leftshift_table_2 = [3,4,5,1,2]
IP_table=[2,6,3,1,4,8,5,7]
IPI_table=[4,1,3,5,7,2,8,6]
EPBox = [4,1,2,3,2,3,4,1]
SPBox=[2,4,3,1]
SBox1 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]

SBox2 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]

def P10(data,table):
    return [data[i-1] for i in table]

def P8(data,table):
    return [data[i - 1] for i in table]

def Leftshift(data,table):
    return [data[i - 1] for i in table]

def Rightshift(data,table):
    return [data[i - 1] for i in table]


def split_data(data):
    # 计算数据的长度
    data_length = len(data)

    # 计算分成两半后的中间索引
    middle_index = data_length // 2

    # 将数据分成左半部分和右半部分
    left_half = data[:middle_index]
    right_half = data[middle_index:]

    return left_half, right_half
# 生成子密文
def Creat_subkey(data):
    data = P10(data,P10_table)
    left_data,right_data =split_data(data)
    left_data_n = Leftshift(left_data,Leftshift_table_1)
    data1 = left_data_n + right_data
    left_data_m = Leftshift(left_data,Leftshift_table_2)
    data2 = left_data_m + right_data
    k1 = P8(data1,P8_table)
    k2 = P8(data2,P8_table)
    return k1,k2

def IP(data,table):
    return [data[i - 1] for i in table]

def EP(data,table):
    return [data[i - 1] for i in table]

def XOR(data1,data2):
    return [a ^ b for a, b in zip(data1, data2)]

def S0(data):
    new_data =[]
    x = data[0]*2+data[1]*1
    y = data[2]*2+data[3]*1
    sbox_value = SBox1[x][y]
    for i in range(2):
        bit = (sbox_value >> (1 - i)) & 1
        new_data.append(bit)
    return new_data

def S1(data):
    new_data =[]
    x = data[0]*2+data[1]*1
    y = data[2]*2+data[3]*1
    sbox_value = SBox2[x][y]
    for i in range(2):
        bit = (sbox_value >> (1 - i)) & 1
        new_data.append(bit)
    return new_data

def SP(data,table):
    return [data[i - 1] for i in table]

# 加密
def Encrypt(plaintext,Key):

    # 子密钥
    k1,k2 = Creat_subkey(Key)

    #初始置换
    data = IP(plaintext, IP_table)

    # 第一次循环
    left_data,right_data = split_data(data)
    right_data2 = EP(right_data,EPBox)
    right_data2 = XOR(right_data2,k1)
    left_data_new,right_data_new = split_data(right_data2)
    left_data_new = S0(left_data_new)
    right_data_new = S1(right_data_new)
    right_data2 = left_data_new+right_data_new
    right_data2 = SP(right_data2,SPBox)
    left_data2 = XOR(right_data2,left_data)

    # 第二次循环
    left_data_n = right_data
    right_data_n = left_data2
    right_data_m = EP(right_data_n,EPBox)
    right_data_m = XOR(right_data_m,k2)
    left_right_data_m,right_right_data_m = split_data(right_data_m)
    left_right_data_m = S0(left_right_data_m)
    right_right_data_m =S1(right_right_data_m)
    right_data_m =left_right_data_m+right_right_data_m
    right_data_m = SP(right_data_m,SPBox)
    left_data_m = XOR(right_data_m,left_data_n)

    # 组合逆初始置换
    ciphertext = left_data_m+right_data_n
    ciphertext = IP(ciphertext,IPI_table)
    return ciphertext

# 解密
def Decrypt(ciphertext,Key):

    # 子密钥
    k1,k2 = Creat_subkey(Key)

    # 初始置换
    ciphertext = IP(ciphertext,IP_table)

    # 第一次循环
    left_data, right_data = split_data(ciphertext)
    right_data2 = EP(right_data, EPBox)
    right_data2 = XOR(right_data2, k2)
    left_data_new, right_data_new = split_data(right_data2)
    left_data_new = S0(left_data_new)
    right_data_new = S1(right_data_new)
    right_data2 = left_data_new + right_data_new
    right_data2 = SP(right_data2,SPBox)
    left_data2 = XOR(right_data2, left_data)

    # 第二次循环
    left_data_n = right_data
    right_data_n = left_data2
    right_data_m = EP(right_data_n, EPBox)
    right_data_m = XOR(right_data_m, k1)
    left_right_data_m, right_right_data_m = split_data(right_data_m)
    left_right_data_m = S0(left_right_data_m)
    right_right_data_m = S1(right_right_data_m)
    right_data_m = left_right_data_m + right_right_data_m
    right_data_m = SP(right_data_m, SPBox)
    left_data_m = XOR(right_data_m, left_data_n)

    # 组合逆初始置换
    plaintext = left_data_m+right_data_n
    plaintext = IP(plaintext,IPI_table)
    return plaintext




# 加密函数
def EncryptText(text, key):
    encrypted_text = ""
    for char in text:
        char_ascii = ord(char)
        char_binary = bin(char_ascii)[2:].zfill(8)  # 转换为8位二进制
        char_encrypted = Encrypt([int(bit) for bit in char_binary], key)
        encrypted_char_ascii = int(''.join(map(str, char_encrypted)), 2)
        encrypted_char = chr(encrypted_char_ascii)
        encrypted_text += encrypted_char
    return encrypted_text

# 解密函数
def DecryptText(encrypted_text, key):
    decrypted_text = ""
    for char in encrypted_text:
        char_ascii = ord(char)
        char_binary = bin(char_ascii)[2:].zfill(8)  # 转换为8位二进制
        char_decrypted = Decrypt([int(bit) for bit in char_binary], key)
        decrypted_char_ascii = int(''.join(map(str, char_decrypted)), 2)
        decrypted_char = chr(decrypted_char_ascii)
        decrypted_text += decrypted_char
    return decrypted_text

# 破解函数
def brute_force(key_start, key_end, plaintext, ciphertext, keys_found):
    for key_decimal in range(key_start, key_end):
        # 将十进制密钥转换为10位二进制密钥列表
        key_binary = format(key_decimal, '010b')
        key = [int(bit) for bit in key_binary]
        ciphertext_temp = DecryptText(ciphertext, key)
        if ciphertext_temp == plaintext:
            keys_found.append(key)  # 将找到的密钥添加到列表中



class Widget(QWidget):
    # Inside your Widget class's __init__ method
    def __init__(self):
        super(Widget, self).__init__()
        self.load_ui()
        # 设置背景图片
        palette = self.palette()
        palette.setBrush(QPalette.Window, QBrush(QPixmap("D:/S-DES/bk.png")))
        self.setPalette(palette)

    def load_ui(self):
        loader = QUiLoader()
        path = os.fspath(Path(__file__).resolve().parent / "form.ui")
        ui_file = QFile(path)
        ui_file.open(QFile.ReadOnly)
        loader.load(ui_file, self)
        ui_file.close()

        # 添加按钮点击事件处理逻辑
        self.pushButton_31 = self.findChild(QPushButton, "pushButton_31")
        self.pushButton_31.clicked.connect(self.on_pushButton_31_clicked)

        self.pushButton_32 = self.findChild(QPushButton, "pushButton_32")
        self.pushButton_32.clicked.connect(self.on_pushButton_32_clicked)

        self.pushButton_33 = self.findChild(QPushButton, "pushButton_33")
        self.pushButton_33.clicked.connect(self.on_pushButton_33_clicked)

        self.pushButton_34 = self.findChild(QPushButton, "pushButton_34")
        self.pushButton_34.clicked.connect(self.on_pushButton_34_clicked)

        self.pushButton_35 = self.findChild(QPushButton, "pushButton_35")
        self.pushButton_35.clicked.connect(self.on_pushButton_35_clicked)

        self.pushButton_36 = self.findChild(QPushButton, "pushButton_36")
        self.pushButton_36.clicked.connect(self.on_pushButton_36_clicked)

        self.pushButton_37 = self.findChild(QPushButton, "pushButton_37")
        self.pushButton_37.clicked.connect(self.on_pushButton_37_clicked)

        self.pushButton_38 = self.findChild(QPushButton, "pushButton_38")
        self.pushButton_38.clicked.connect(self.on_pushButton_38_clicked)

        self.pushButton_39 = self.findChild(QPushButton, "pushButton_39")
        self.pushButton_39.clicked.connect(self.on_pushButton_39_clicked)

        self.pushButton_40 = self.findChild(QPushButton, "pushButton_40")
        self.pushButton_40.clicked.connect(self.on_pushButton_40_clicked)


        # 寻找并访问 stackedWidget
        self.stackedWidget = self.findChild(QStackedWidget, "stackedWidget")

        # 寻找并访问 QTextEdit
        self.textEdit_16 = self.findChild(QTextEdit, "textEdit_16")
        self.textEdit_17 = self.findChild(QTextEdit, "textEdit_17")
        self.textEdit_18 = self.findChild(QTextEdit, "textEdit_18")
        self.textEdit_19 = self.findChild(QTextEdit, "textEdit_19")
        self.textEdit_20 = self.findChild(QTextEdit, "textEdit_20")



    # 按钮点击事件处理逻辑
    def on_pushButton_31_clicked(self):
        self.stackedWidget.setCurrentIndex(0)

    def on_pushButton_32_clicked(self):
        self.stackedWidget.setCurrentIndex(1)

    def on_pushButton_33_clicked(self):
        self.stackedWidget.setCurrentIndex(2)

    def on_pushButton_34_clicked(self):
        self.stackedWidget.setCurrentIndex(4)

    def on_pushButton_35_clicked(self):
        self.stackedWidget.setCurrentIndex(3)

    # 基本测试
    def on_pushButton_36_clicked(self):
        self.lineEdit_key = self.findChild(QLineEdit, "lineEdit_34")
        key = self.lineEdit_key.text()
        key = key.replace("，", ",")  # 将中文逗号替换为英文逗号
        key_list = [int(x) for x in key.split(',')]
        self.lineEdit_plaintext = self.findChild(QLineEdit, "lineEdit_35")
        plaintext = self.lineEdit_plaintext.text()
        plaintext = plaintext.replace("，", ",")  # 将中文逗号替换为英文逗号
        plaintext_list = [int(x) for x in plaintext.split(',')]
        ciphertext = Encrypt(plaintext_list, key_list)
        ciphertext_str = ','.join(map(str, ciphertext))
        self.textEdit_16.clear()  # 清空文本框内容
        self.textEdit_16.insertPlainText("加密后的密文为：" + ciphertext_str + "\n")

    # 加密操作
    def on_pushButton_37_clicked(self):
        self.lineEdit_key = self.findChild(QLineEdit, "lineEdit_36")
        key = self.lineEdit_key.text()
        key = key.replace("，", ",")  # 将中文逗号替换为英文逗号
        key_list = [int(x) for x in key.split(',')]
        self.lineEdit_plaintext = self.findChild(QLineEdit, "lineEdit_37")
        plaintext = self.lineEdit_plaintext.text()
        ciphertext = EncryptText(plaintext, key_list)
        self.textEdit_17.clear()  # 清空文本框内容
        self.textEdit_17.insertPlainText("加密后的密文为：" + ciphertext+"\n")

    # 解密操作
    def on_pushButton_38_clicked(self):
        self.lineEdit_key = self.findChild(QLineEdit, "lineEdit_38")
        key = self.lineEdit_key.text()
        key = key.replace("，", ",")  # 将中文逗号替换为英文逗号
        key_list = [int(x) for x in key.split(',')]
        self.lineEdit_ciphertext = self.findChild(QLineEdit, "lineEdit_39")
        ciphertext = self.lineEdit_ciphertext.text()
        decrypted_text = DecryptText(ciphertext, key_list)
        self.textEdit_18.clear()  # 清空文本框内容
        self.textEdit_18.insertPlainText("解密后的明文为：" + decrypted_text+"\n")

    # 暴力破解
    def on_pushButton_40_clicked(self):
        self.lineEdit_plaintext = self.findChild(QLineEdit, "lineEdit_43")
        plaintext = self.lineEdit_plaintext.text()
        self.lineEdit_ciphertext = self.findChild(QLineEdit, "lineEdit_44")
        ciphertext = self.lineEdit_ciphertext.text()
        self.textEdit_20.clear()  # 清空文本框内容
        self.textEdit_20.insertPlainText("暴力破解中--------\n")
        # 设置要尝试的密钥范围
        key_start = 0
        key_end = 255  # 对应10位二进制密钥的最大值

        # 记录开始时间
        start_time = time.time()

        # 创建多个线程来并行尝试不同范围的密钥
        threads = []
        keys_found = []  # 存储找到的密钥
        for i in range(4):  # 假设使用3个线程
            thread = threading.Thread(target=brute_force, args=(key_start, key_end, plaintext, ciphertext, keys_found))
            threads.append(thread)
            key_start = key_end + 1
            key_end = key_start + 255  # 均分密钥范围

        # 启动线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 记录结束时间
        end_time = time.time()

        # 打印找到的密钥
        if keys_found:
            self.textEdit_20.insertPlainText("破解成功，密钥为：\n")
            self.textEdit_20.insertPlainText(', '.join(map(str, keys_found))+"\n")
        else:
            self.textEdit_20.insertPlainText("未找到匹配的密钥\n")

        # 计算并打印破解所花费的时间
        elapsed_time = end_time - start_time
        self.textEdit_20.insertPlainText("花费时间：{:.6f}秒\n".format(elapsed_time))


    # 验证相同明文，不同密钥，是否可以加密出相同的密文
    def on_pushButton_39_clicked(self):
        self.lineEdit_plaintext = self.findChild(QLineEdit, "lineEdit_40")
        plaintext = self.lineEdit_plaintext.text()
        self.lineEdit_key1 = self.findChild(QLineEdit, "lineEdit_41")
        key1 = self.lineEdit_key1.text()
        key = key1.replace("，", ",")  # 将中文逗号替换为英文逗号
        key_list1 = [int(x) for x in key.split(',')]
        self.lineEdit_key2 = self.findChild(QLineEdit, "lineEdit_42")
        key2 = self.lineEdit_key2.text()
        key = key2.replace("，", ",")  # 将中文逗号替换为英文逗号
        key_list2 = [int(x) for x in key.split(',')]
        ciphertext1 = EncryptText(plaintext, key_list1)
        ciphertext2 = EncryptText(plaintext, key_list2)
        self.textEdit_19.clear()  # 清空文本框内容
        self.textEdit_19.insertPlainText("密钥1加密后的密文：" + ciphertext1 + "\n")
        self.textEdit_19.insertPlainText("密钥2加密后的密文：" + ciphertext2 + "\n")

        if (ciphertext1 == ciphertext2):
            self.textEdit_19.insertPlainText("相同明文，不同密钥，可以加密出相同的密文,该加密系统没有封闭性！\n")
        else:
            self.textEdit_19.insertPlainText("相同明文，不同密钥，不可以加密出相同的密文,该加密系统有封闭性！\n")


if __name__ == "__main__":
    app = QApplication([])
    widget = Widget()
    widget.show()
    sys.exit(app.exec_())


