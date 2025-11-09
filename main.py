import requests
import logging
from telebot import TeleBot
from telebot.types import Message, ReplyKeyboardMarkup, KeyboardButton

# إعداد السجلات
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssh_telebot")

# إنشاء البوت
bot = TeleBot("7973768312:AAEeUlzcqAp58e4M7n4iCBpIWc2pz5XEsH0")

# إعدادات APIs (متبقية كما هي)
APIS = {
    "MAYNET": "https://painel.meowssh.shop:5000/test_ssh_public",
    "MEOW": "http://158.69.20.4:5000/test_ssh_public"
}
PAYLOAD = {"store_owner_id": 1}
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

# إنشاء الكيبورد الثابت
def create_main_keyboard():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    btn_maynet = KeyboardButton("🌐 MAYNET")
    btn_meow = KeyboardButton("🐱 Meow-DT")
    keyboard.add(btn_maynet, btn_meow)
    return keyboard

@bot.message_handler(commands=['start'])
def start_handler(message: Message):
    welcome_text = (
        "👋 أهلاً بك في بوت SSH\n\n"
        "🔹 اختر أحد الخيارات من الكيبورد:"
    )
    bot.reply_to(message, welcome_text, reply_markup=create_main_keyboard())

@bot.message_handler(func=lambda message: message.text == "🌐 MAYNET")
def maynet_handler(message: Message):
    """زر MAYNET يعطي حساب من Meow-DT"""
    create_ssh_account(message, "MEOW")  # تغيير هنا

@bot.message_handler(func=lambda message: message.text == "🐱 Meow-DT")
def meow_handler(message: Message):
    """زر Meow-DT يعطي حساب من MAYNET"""
    create_ssh_account(message, "MAYNET")  # تغيير هنا

def create_ssh_account(message: Message, api_type: str):
    """دالة مساعدة لإنشاء الحسابات"""
    try:
        api_url = APIS.get(api_type)
        if not api_url:
            bot.reply_to(message, "❌ نوع API غير معروف", reply_markup=create_main_keyboard())
            return
            
        # إرسال رسالة الانتظار
        wait_msg = bot.reply_to(message, "⏳ جاري إنشاء الحساب...")
        
        response = requests.post(api_url, json=PAYLOAD, headers=HEADERS, timeout=10)
        
        # حذف رسالة الانتظار
        bot.delete_message(message.chat.id, wait_msg.message_id)
        
        if response.status_code in [200, 201]:
            data = response.json()
            usuario = data.get("Usuario", "N/A")
            senha = data.get("Senha", "N/A")
            
            # النتيجة النهائية فقط الاسم وكلمة المرور
            reply = f"👤 Usuario: {usuario}\n🔑 Senha: {senha}"
            bot.reply_to(message, reply, reply_markup=create_main_keyboard())
        else:
            bot.reply_to(message, f"❌ خطأ {response.status_code}", reply_markup=create_main_keyboard())
            
    except Exception as e:
        logger.error(f"{api_type} Error: {e}")
        bot.reply_to(message, f"🚨 خطأ بالاتصال", reply_markup=create_main_keyboard())

@bot.message_handler(func=lambda message: True)
def echo_all(message: Message):
    """الرد على أي رسالة أخرى"""
    if message.text.startswith('/'):
        bot.reply_to(message, "❌ أمر غير معروف", reply_markup=create_main_keyboard())
    else:
        bot.reply_to(message, "🔹 اختر أحد الخيارات من الكيبورد:", reply_markup=create_main_keyboard())

if __name__ == "__main__":
    logger.info("✅ بدء تشغيل البوت مع تبديل الأدوار...")
    bot.polling(none_stop=True)
