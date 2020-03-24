#!/usr/bin/python3
# -*- coding:utf-8 -*-


import argparse, sys, threading, re, socket, time
from multiprocessing import Queue, Process, TimeoutError
from urllib.parse import urlparse
import multiprocessing
import gevent
from gevent import monkey,queue;
monkey.patch_all()
import requests
# 解决443的问题
requests.packages.urllib3.disable_warnings()

class Scanner(object):

    """docstring for Scanner"""
    def __init__(self, *params):
        self.scan_count, self.found_count = params
        self.scan_count_local = 0
        # 存放任务的队列
        self.domain = ''
        self.results = {}
        self.url_queue = queue.Queue()
        self.lock = threading.Lock()
        self.result_queue = queue.Queue()
        self.adminPath = loadAdminPath()
        self.headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.80 Safari/537.36'}


    def _init_task(self, domain):
        self.domain = domain
        if self.isLive(self.domain):
            for line in self.adminPath:
                scanUrl = self.domain + "/" + line.strip().replace("/", "")
                self.url_queue.put(scanUrl)
        else:
            return
    def isLive(self, domain):
        res = None
        try:
            url = 'http://'+ domain + '/'
            res = requests.get(url, verify=False,headers=self.headers, timeout=2)
        except Exception as e:
            res = None
        if res is None:
            try:
                url = 'https://'+ domain + '/'
                res = requests.get(url, verify=False,headers=self.headers, timeout=2)
            except:
                res = None
        if res == None:
            return False
        else:
            return True

    def tiny_scan(self):
        while True:
            if self.url_queue.empty():
                break
            try:
                self.lock.acquire()
                # 扫描数目+1
                if self.scan_count_local > 0:
                    self.scan_count.value += self.scan_count_local
                else:
                    self.scan_count_local = 0
                self.lock.release()
                url = self.url_queue.get(timeout=3.0)
            except gevent.queue.Empty as e:
                print("[tiny_scan] %s" % str(e))
                break
            try:
                res = requests.head('http://'+ url, verify=False,headers=self.headers, timeout=2)
            except Exception as e:
                res = None
            if res is None:
                try:
                    res = requests.head('https://'+ url, verify=False,headers=self.headers, timeout=2)
                except:
                    res = None
            if res == None:
                continue
            code = res.status_code
            if code == 404:
                continue


            if(res.headers['server'] != ''):
                server = res.headers['server']
            else:
                server = 'NULL'
            self.scan_count_local += 1
            # 添加结果
            results = {'url':url, 'status':code, 'server':server }
            self.result_queue.put(results)

    def run(self, threads=500):
        # 默认开启50协程
        tinyThread = [gevent.spawn(self.tiny_scan) for i in range(threads)]
        gevent.joinall(tinyThread)

    def scan(self, threads=10):
        try:
            all_thread = []
            for i in range(threads):
                t = threading.Thread(target = self.run)
                t.start()
                all_thread.append(t)
            for t in all_thread:
                t.join()
            print("%s scan OK" % self.domain)
            return self.domain
        except Exception as e:
            print("[scan exception] %s" % str(e))


def parse_args():
    parser = argparse.ArgumentParser(description="A tool of high cocurrency scan admin Page ")
    parser.add_argument('-t', '--target',metavar='baidu.com', dest='target', type='str', help=u'target loading' )
    args = parser.parse_args()
    if args.target == None:
        parser.print_help()
        sys.exit()
    return args


def parse_url(url):
    _ = urlparse(url, 'http')
    if not _.netloc:
        _ = urlparse('http://' + url, 'http')
    return _.scheme, _.netloc, _.path if _.path else '/'


def user_abort(sig, frame):
    exit(-1)

def loadAdminPath():
    path = []
    with open('common.txt') as f:
        for line in f:
            path.append(line.strip())
    return path

def runProccess(scan_count,found_count,qResults, qTargets, target_process_done):
    s = Scanner(scan_count,found_count)
    while True:
        try:
            target = qTargets.get(timeout=0.5)
        except Exception as e:
            if target_process_done.value:
                break
            else:
                continue
        if target['url']:
            # print(target['url'])
            s._init_task(target['url'])
        # threadNum
        try:
            host = s.scan()
            # if results:
            #     qResults.put((host, results))
        except Exception as e:
            print("[runProccess] %s" % str(e))


def getTarget(domain, qTargets):
    print("[+] Init Target from IP or Domain")
    scheme, netloc, path = parse_url(domain)
    if not netloc:
        # 判断是不是地址
        if re.search(r'\d+\.\d+\.\d+\.\d+', domain.split(':')[0]):
            host = domain.split(':')[0].stip()
    else:
        host = netloc
    try:
        ipAddr = socket.getaddrinfo(host, 'http')[0][4][0]
    except Exception as e:
        ipAddr = ""
        print("[-] Get Target IP Failed...%s" % e)
        print("[-] Waiting Exit(0).....")
        sys.exit(0)
    reg = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.'
    ipsuffix = re.findall(reg,ipAddr)[0]
    # print(ipsuffix)

    # 生成C段IP
    count = 0
    for i in range(1,256):
        ip = ipsuffix + str(i)
        qTargets.put({'url': ip})
        count += 1
    target_process_done.value = 1
    print("%s targets left to scan" % count)


def main():
    # 1.获取运行参数
    # args = parse_args()
    domain = 'www.csg.cn'
    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)
    multiprocessing.Value('i', 0)
    # 存放最终结果
    qResults = multiprocessing.Queue()
    # 存放扫描目标
    qTargets = multiprocessing.Queue()
    # 动态进程竞争信号量
    global target_process_done
    target_process_done = multiprocessing.Value('i', 0)
    try:
        print("[+] Scanner start running....")
        proccesses = 4
        print("[+] Start %s scan proccess" % proccesses)
        start_time = time.time()
        # 开一个进程去生成目标队列
        t = threading.Thread(target=getTarget, args=(domain, qTargets))
        t.start()
        all_process = []
        for i in range(proccesses):
            p  = Process(target=runProccess, args=(scan_count,found_count,qResults, qTargets, target_process_done))
            all_process.append(p)
            p.start()

        # 当前线程阻塞等待任务完成
        t.join()
        for p in all_process:
            p.join()
        print("scan_ount: %s" % scan_count.value)
        print("Task Finished....%.1f" % (time.time() - start_time))
        # print(qTargets.get())
    except KeyboardInterrupt as e:
        print("[ERROR] User aborted the scan!")
        # 强制结束子进程
        for p in all_process:
            p.terminate()
    except Exception as e:
        print("[ERROR] {}".format(str(e)))

def test():
    print(getTarget('www.csg.cn'))


if __name__ == '__main__':
    main()
    # test()