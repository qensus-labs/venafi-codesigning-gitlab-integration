import os

support_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'support'))


def read_product_version():
    with open(os.path.join(support_dir, 'version.txt'), 'r', encoding='UTF-8') as f:
        return f.read().strip()


def main():
    print(read_product_version())


if __name__ == '__main__':
    main()
