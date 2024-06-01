<p align="center">
    <a target="_blank" href="https://github.com/JJLibra/Astar">
        <img src="https://github.com/JJLibra/XScanner/blob/main/qt/logo.png" alt="astar-logo" width="150" data-width="150" data-height="150">
    </a>
</p>

<h1 align="center">XScanner</h1>

<h2 align="center">🎨Just a simple port scanner</h2>

<p align="center">
    <a target="_blank" href="https://github.com/JJLibra">
      <img style="display:inline-block;margin:0.2em;" alt="Author" src="https://img.shields.io/badge/Author-Junjie Li-blue.svg?logo=autoit&style=flat">
    </a>
    <a target="_blank" href="https://github.com/JJLibra/XScanner">
      <img style="display:inline-block;margin:0.2em;" alt="GitHub Repo stars" src="https://img.shields.io/github/stars/JJLibra/XScanner?style=social">
    </a>
    <a target="_blank" href="https://github.com/JJLibra/XScanner">
      <img style="display:inline-block;margin:0.2em;" alt="Qt" src="https://img.shields.io/badge/Framework-Qt-green.svg?logo=Qt&style=flat">
    </a>
</p>

## ⚠ Precautions

The project paths must all be in English, otherwise an error will be reported during build.

The icon may not be displayed when running for the first time. It may be that the import was not successful.
After opening the project in QT Creator, it is recommended to re-add the icon file in `Resources` - `img_src.qrc` - `Add Existing File`.

This project uses raw socket programming and winpacp library for sending, receiving and analyzing messages.

Therefore, before downloading the source code for secondary development, you need to configure the winpacp environment and modify the corresponding reference library path in the `.pro` file. You can [refer to this blog](https://blog.csdn.net/Mr_robot_strange/article/details/116016418).

## 🚀 How To Use ?

This project is developed using the QT framework C++ and the development environment is Windows.

The project has been packaged into an `.exe` file and is ready to use.📦

It is also very simple to perform secondary development based on the source code. Just use Qt Creater to open the project. Of course, you can also use an editor such as VScode configured with the Qt environment to open it.

Currently the software only supports the following functions:
1. Scan Class C subnets to find live hosts.
2. Scan the specified host IP for port openness and service type.
3. Scan type: Ping, TCP, TCP-SYN, TCP-ACK, TCP-FIN, UDP.
4. Supports customizing the number of threads and waiting response delay.
5. Save scan log.
6. The port service type is not accurate and is for reference only.
7. ...(todo)

It is very easy to use. Without further ado, I believe you, as a smart person, can get started quickly.

## 🤝 Candidates are very welcome to contribute code.

1. Contribute to this endeavor, `Fork` the present undertaking.
2. Establish your distinctive branch of characteristics.
```bash
git checkout -b feature/AmazingFeature
```
3. Submit your modifications forthwith.
```bash
git commit -m 'Add some AmazingFeature'
```
4. Propagate your branch to the remote repository with due diligence.
```bash
git push origin feature/AmazingFeature
```
5. Submit a formal pull request for consideration.

## License

[Apache 2.0](https://github.com/JJLibra/XScanner/blob/main/LICENSE)
