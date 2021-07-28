# Werkzeug Console Pin
Yet another Werkzeug Console Pin Exploit Explanation

As explained by Carlos Polop in ![Hacktricks.xyz](https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug), this exploit is to access /console from Werkzeug when it requires a pin. This Console is a debug console that is Python based, which means, once you access this debug console, you could launch a reverse shell.

## Pin Protected
Once you find out Werkzeug Console is pin-protected, you need to find a way to get this pin and access the debug console, right? Well, other people had put some effort in getting this, which is the base of my work here.

Here you can find how to generate this pin:
* [Daehee Park' Werkzeug Console PIN Exploit](https://www.daehee.com/werkzeug-console-pin-exploit/)
* [https://ctftime.org/writeup/17955](https://ctftime.org/writeup/17955)

Taking 
