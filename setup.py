import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="alipay_dc_client",
    version="0.1.1018",
    author="Tianyu",
    author_email="tianyurui@gmail.com",
    description="支持支付宝公钥证书方式签名的客户端",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    install_requires=["pycryptodome>=3.9.8", "pyOpenSSL>=19.1.0"],
    entry_points={
    },
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
