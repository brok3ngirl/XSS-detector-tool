# XSS-detector-tool
本项目是对上海戎磐公司面试问题的简单处理。
本项目分为两个模块，一个是基于渗透测试的视角(attack),另外是对于php页面源代码的审计(test)
对于php页面源代码的审计仅仅做了危险函数正则匹配和参数实体化的检测。


usage: crosscause.py [-h] --moudle MOUDLE [--url URL] [--page PAGE]
For example:
'''
└─$ python crosscause.py -m test -p test.php
 ___    ___ ________   ________           ________   ________          ___       __   ________      ___    ___ 
|\  \  /  /|\   ____\ |\   ____\         |\   ___  \|\   __  \        |\  \     |\  \|\   __  \    |\  \  /  /|
\ \  \/  / | \  \___|_\ \  \___|_        \ \  \\ \  \ \  \|\  \       \ \  \    \ \  \ \  \|\  \   \ \  \/  / /
 \ \    / / \ \_____  \\ \_____  \        \ \  \\ \  \ \  \\\  \       \ \  \  __\ \  \ \   __  \   \ \    / / 
  /     \/   \|____|\  \\|____|\  \        \ \  \\ \  \ \  \\\  \       \ \  \|\__\_\  \ \  \ \  \   \/  /  /  
 /  /\   \     ____\_\  \ ____\_\  \        \ \__\\ \__\ \_______\       \ \____________\ \__\ \__\__/  / /    
/__/ /\ __\   |\_________\\_________\        \|__| \|__|\|_______|        \|____________|\|__|\|__|\___/ /     
|__|/ \|__|   \|_________\|_________|                                                             \|___|/      
                                                                                                               
                                                                                                               
[blue safe]
[+]following maybe have XSS vuln:
Line 2: echo $_GET['name']; // Unsafe
  -> Directly echoing user input
  [-]Warning: Input is not sanitized.
Line 3: print $_POST['input']; // Unsafe
  -> Directly printing user input
  [-]Warning: Input is not sanitized.
Line 4: echo "<div>" . $_REQUEST['data'] . "</div>"; // Unsafe
  -> Embedding user input in HTML tags
  [-]Warning: Input is not sanitized.
