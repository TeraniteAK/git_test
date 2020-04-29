1# 2020.4.4
# 要求
# 1.自动soot处理apk
# 2.自动提取特征，做成csv文件，一个bb一行（空bb不算）

import subprocess
import os
import time
import sys
import pandas as pd
import re
from functools import cmp_to_key

# 1.自动soot处理apk
# 调用linux系统命令，执行sh脚本
# 2.parse


# 全局变量
temp_df = pd.DataFrame()
output_df = pd.DataFrame()
# APK_NAME = ''
# class_name = ''


# 确定某个点是否为某个点的father, 返回Ture/False
# 不能超过start_point
# 采用stack的深度优先遍历，没有用递归（递归都有点问题）
def find_father(father_graph, child, father, start_point):
    visited = []
    stack = []
    fathers = father_graph[child]
    for item in fathers.split('#'):
        stack.append(item)
    while(stack != []):
        print('stack is: ', end='')
        print(stack)
        node_index = stack.pop()
        if(node_index not in visited):
            visited.append(node_index)
        else:
            continue
        # 找到最高那个点了还没找到father
        if(node_index == ''):
            return False
        # 找到start_point了还没找到father
        if(node_index == start_point):
            return False
        # 找到father
        if(node_index == father):
            return True
        fathers = father_graph[node_index]
        for item in fathers.split('#'):
            stack.append(item)
    return False


# 判断该句是否为安卓API调用，因为比较复杂就单独写个函数
# return True/False
# node_index：目前遍历到的结点index（初始值为要判断的结点index）
# last_flag: 0: 没有从前面递归来，初始值也为0
#            1: 从前面递归过来的
# last_var: last_flag = 0时，last_var=''空串，初始值也为''
#           last_flag = 1时，last_var保存传递过来需要找他是不是android的变量名，比如r6, $r7这种
# file_name: 传入该dot的文件名，方便@this等语句的找
def is_android_API(father_graph, label_graph, node_index, last_flag, last_var, file_name):
    if(node_index == ''):
        return False
    # 根据node_index提取那一个节点的label是啥
    statement = label_graph[node_index]
    statement_List = re.findall('label=".*"', statement)
    # 没有找到label语句（可能是表明edge语句），所以继续递归
    if (statement_List == []):
        return False
        # 这一段应该在find_feature_1中写，这里面要递归的地方只有那种往上找rx定义的
        # # 遍历所有路径往上找
        # fathers = father_graph[node_index]
        # # 找到根节点了还没找到符合条件的，返回False
        # if (fathers == ''):
        #     return False
        # fathers = fathers.split('#')
        # for item in fathers:
        #     is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    else:
        statement_label = statement_List[0][7:-1]

    variable_name_List = re.findall('\$?r\d+', statement_label)
    # 以下是3种第一次匹配返回False的情况
    # 匹配不到变量名，返回False
    if (variable_name_List == []):
        if(last_flag == 0):
            return False
        # 如果在非第一次匹配时没有匹配到变量则循环
        else:
            # 遍历所有路径往上找
            fathers = father_graph[node_index]
            # 如果已经找到根节点了，就返回False
            if (fathers == ''):
                return False
            fathers = fathers.split('#')
            for item in fathers:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)

    # specialinvoke语句，返回False
    if ('specialinvoke' in statement_label and last_flag == 0):
        return False
    # 第一次就匹配到new语句，返回False（我们要匹配的是慢慢找上来的new语句）
    if ('new' in statement_label and last_flag == 0):
        return False

    first_variable = variable_name_List[0]

    # 开始匹配各种情况，case1~6
    # case1:rx = new ...，这种如果不是第一次就可以确定
    match_case1 = re.findall('\$?r\d+ = new android.*', statement_label)
    # 没有匹配到或者var名称不对应，就继续往上找
    if (match_case1 != [] or last_var != first_variable):
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 如果已经找到根节点了，就返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if(last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    # 找到了就说明是android开头API，并且如果递归上来的var名称和现在语句的第一个var匹配，返回True
    elif (last_var == first_variable):
        return True

    # case2:rx = () ry，强制类型转换，也能确定
    match_case2 = re.findall('\$?r\d+ = \(android.*\) \$?r\d+', statement_label)
    # 没有匹配到或者var名称不对应，就继续往上找
    if (match_case2 != [] or last_var != first_variable):
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    # 找到了就要判断文件名
    elif (last_var == first_variable):
        return True

    # case3:rx := @this
    # 后面发现这个情况应该不行，因为android开头的文件已经被跳过了，所以这种情况是不会遇到的
    match_case3 = re.findall('\$?r\d+ := @this', statement_label)
    # 没有匹配到或者var名称不对应，就继续往上找
    if (match_case3 != [] or last_var != first_variable):
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    # 如果文件名以android开头就对了，返回True
    elif (file_name.startswith('android')):
        return True

    # case4:rx := parameter0
    match_case4 = re.findall('\$?r\d+ := @parameter\d+', statement_label)
    # 没有匹配到或者var名称不对应，就继续往上找
    if (match_case4 != [] or last_var != first_variable):
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    # 这个可以在dot文件名的arg表里面按顺序找。
    elif (last_var == first_variable):
        args_match = re.findall('\(.*\)', file_name)
        arg_index_match = re.findall('\d+', match_case4[0])
        arg_index = arg_index_match[1]
        if (args_match != []):
            args = args_match[0].replace('(', '').replace(')', '').split(',')
            arg_index = int(arg_index)
            arg = args[arg_index]
            if (arg.startswith('android')):
                return True
            else:
                # 遍历所有路径往上找
                fathers = father_graph[node_index]
                # 找到根节点了，返回False
                if (fathers == ''):
                    return False
                fathers = fathers.split('#')
                for item in fathers:
                    if (last_flag == 0):
                        return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
                    else:
                        return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)

    # case5:rx = ry.this$0
    # 后面发现这个情况应该不行，因为android开头的文件已经被跳过了，所以这种情况是不会遇到的
    match_case5 = re.findall('\$?r\d+ = \$?r\d+\.this', statement_label)
    # 没有匹配到或者var名称不对应，就继续往上找
    if (match_case5 != [] or last_var != first_variable):
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    # 如果文件名以android开头就对了，返回True
    elif (file_name.startswith('android')):
        return True

    # case6:rx.API(args) 这种要么递归上去要么作为起点往上走
    match_case6 = re.findall('\$?r\d+\..*\(.*\)', statement_label)
    # 不管匹配到的rx是不是和label相同的都要往上走
    if (match_case6 != []):
        # 如果是第一次就开始第一次递归
        """
        if(last_var == '' ):
            return is_android_API(father_graph, label_graph, node_index, 1, first_variable)
        if(last_var == first_variable):
            return is_android_API(father_graph, label_graph, node_index, 1, first_variable)
        if(last_var != first_variable):
            return is_android_API(father_graph, label_graph, node_index, 1, last_var)
        """
        if (last_var != first_variable):
            first_variable = last_var
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    else:
        # .....离谱儿 都是一样的。。。
        if (last_var != first_variable):
            first_variable = last_var
        # 遍历所有路径往上找
        fathers = father_graph[node_index]
        # 找到根节点了，返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            if (last_flag == 0):
                return is_android_API(father_graph, label_graph, item, 1, first_variable, file_name)
            else:
                return is_android_API(father_graph, label_graph, item, 1, last_var, file_name)


# 向上找某个arg是不是androidAPI
# var：要比较的var，一直不变
# node_index：当前遍历到的node_index，会随着遍历变
# last_flag用于判断case2/case3
# last_flag = 0, 初始化, 无效果
# last_flag = 2/3分别代表case2和case3
# case1: startswith('android')
# case2: rx -> rx = ry.API -> ry = new android.../(android) ...
# case3: rx = ry.API -> ry = new android.../(android) ...
# var: 0/rx (初始化为0, 经过一次循环后可以填上)
def up_traversal_rx(arg, father_graph, node_index, last_flag, var):
    # case1: startswith('android')
    if(arg.startswith('android') and last_flag == 0):
        return True

    match = re.findall('\$?r\d+', arg)
    # 没匹配到rx, 可能是edge
    if(match == []):
        # 往上找父亲
        fathers = father_graph[node_index]
        # 如果已经找到根节点了，就返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            return up_traversal_rx(arg, father_graph, item, 0, 0)

    now_var = match[0]
    # case2: rx -> rx = ry.API -> ry = new android.../(android) ...
    if('.' not in arg and last_flag == 0):
        # 往上找父亲
        fathers = father_graph[node_index]
        # 如果已经找到根节点了，就返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            return up_traversal_rx(arg, father_graph, item, 2, now_var)

    # case3: rx = ry.API -> ry = new android.../(android) ...
    match_statement = re.findall('\$?r\d+ = \$?r\d+\.', arg)
    if (match_statement != [] and last_flag == 0):
        # 往上找父亲
        fathers = father_graph[node_index]
        # 如果已经找到根节点了，就返回False
        if (fathers == ''):
            return False
        fathers = fathers.split('#')
        for item in fathers:
            return up_traversal_rx(arg, father_graph, item, 3, now_var)

    # case2_1: case2往上找的情况
    if (last_flag == 2):
        # 没找到匹配的
        if (now_var != var):
            # 往上找父亲
            fathers = father_graph[node_index]
            # 如果已经找到根节点了，就返回False
            if (fathers == ''):
                return False
            fathers = fathers.split('#')
            for item in fathers:
                return up_traversal_rx(arg, father_graph, item, 2, var)
        if (now_var == var):
            # 区别两种情况
            # 1. rx.API, 这种只是一个调用语句, 无法得出rx是不是一个API
            # ？？？？？？如果找到了rx.API那是不是说明rx一定是个对象实例而不是一个API
            # ？？？？？？那startswith('android')那个也不对了 分不清楚是API还是对象的实例
            # match_1 = re.findall('\$?r\d+\.', arg)
            # if (match_1 != []):
            #     match_2 = re.findall('\$?r\d+ = ', arg)
            #     if(match_2 != []):
            #         return up_traversal_rx(arg, father_graph, item, 3, var)
            #     else：


            match = re.findall('\$?r\d+ = \$?r\d+\.', arg)
            if(match == []):
                return False
            else:
                return up_traversal_rx(arg, father_graph, item, 3, var)

    # case3_1:case3往上找的情况或case2往上找第二个情况
    if (last_flag == 3):
        # 没找到匹配的
        if (now_var != var):
            # 往上找父亲
            fathers = father_graph[node_index]
            # 如果已经找到根节点了，就返回False
            if (fathers == ''):
                return False
            fathers = fathers.split('#')
            for item in fathers:
                return up_traversal_rx(arg, father_graph, item, 3, var)
        if (now_var == var):
            match = re.findall('\$?r\d+ = new android', arg)
            if(match == []):
                match = re.findall('\$?r\d+ = \(android', arg)
                if(match == []):
                    return False
                else:
                    return True
            else:
                return True
    # 所有的情况都不匹配的话 就False(应该是指找到var对应 但是后面的不是android API的)
    # return False


# 判断该句是否存在安卓API是arg的情况
# 逻辑类似is_android_API
# return True/False
# last_flag: 0: 没有从前面递归来，初始值也为0
#            2: case_2的标志
#            3: case_3的标志
# last_var: last_flag = 0时，last_var=''空串，初始值也为''
#           last_flag = 2/3时，last_var保存传递过来需要找他是不是android的变量名，比如r6, $r7这种

# 相当于我第一层找statement_label的循环在find_feature_1里面
# 但是我case2和case3的循环都必须在is_android_API_arg里面了, 这个循环我单独写为了up_traversal_rx
# case2/3也在up_traversal_rx里面
def is_android_API_arg(father_graph, label_graph, node_index, last_flag):
    if (node_index == ''):
        return False
    # 根据node_index提取那一个节点的label是啥
    statement = label_graph[node_index]
    statement_List = re.findall('label=".*"', statement)
    # 没有找到label语句（可能是表明edge语句），所以继续递归
    if (statement_List == []):
        return False
        # 这一段应该在find_feature_1中写，这里面要递归的地方只有那种往上找rx定义的
        # # 遍历所有路径往上找
        # fathers = father_graph[node_index]
        # # 找到根节点了还没找到符合条件的，返回False
        # if (fathers == ''):
        #     return False
        # fathers = fathers.split('#')
        # for item in fathers:
        #     is_android_API(father_graph, label_graph, item, 1, last_var, file_name)
    else:
        statement_label = statement_List[0][7:-1]

    # specialinvoke语句，返回False
    if('specialinvoke' in statement_label and last_flag == 0):
        return False
    # 第一次就匹配到new语句，返回False（我们要匹配的是慢慢找上来的new语句）
    if ('new' in statement_label and last_flag == 0):
        return False


    # 第一次才会parse args，因为之后的循环必然是要匹配var的
    args_match_List = re.findall('\(.*\)', statement_label)
    # args为空，返回False
    if(args_match_List == []):
        return False
    args_match = args_match_List[0]
    args = args_match.split(',')

    # 对每一个arg都要往上找 比较麻烦感觉
    # 要保证这个循环只在第一次有
    results = []
    for item in args:
        results.append(up_traversal_rx(item, father_graph, node_index, 0, 0))

    # 找遍所有arg, 其中有一个满足条件, 返回True
    if (True in results):
        return True
    # 找遍所有arg都没有满足条件的, 返回False
    return False


# find_feature_1中深度优先遍历
# visited, feature_2, feature_3, feature_4, feature_5
# 很烦 其实就是深度优先遍历的递归实现 但是不知道为什么不好用 所以决定用非递归实现(自建栈)
def down_traversal(child_graph, father_graph, label_graph, file_name,
                   node_index, end_point):

    # 非递归实现
    visited = []
    # results for feature2~5
    results = [0, 0, 0, 0]
    stack = []
    children = child_graph[node_index]
    results[0] += 1
    for item in children.split('#'):
        stack.append(item)
    while (stack != []):
        node_index = stack.pop()
        if(node_index == ''):
            continue
        if(node_index == end_point):
            continue
        else:
            # 先parse
            if (node_index not in visited):
                visited.append(node_index)
                if (is_android_API(father_graph, label_graph, node_index, 0, '', file_name)):
                    results[1] = 1
                    results[3] += 1
                if (is_android_API_arg(father_graph, label_graph, node_index, 0)):
                    results[2] = 1
                results[0] += 1
            # 再入栈
            children = child_graph[node_index]
            for item in children.split('#'):
                stack.append(item)
    return results


# 寻找特征2-5
# 2: bb代码行数  3：是否有android API调用
# 4：API调用的参数中是否有android API
# 5：android API调用的次数
# label应该是全程的？？之后要改一下
def find_features_1(father_graph, child_graph, label_graph, start_point, end_point, left_child_point,
                    right_child_point, file_path):

    print('进入find_features_1')

    # 因为是两个bb, 所以用一个数组, 分别代表bb1和bb2

    file_name = file_path.split('/')[-1]

    # bb1:
    if (left_child_point == end_point):
        result_b1 = [0, 0, 0, 0]
        pass
    else:
        # def down_traversal(child_graph, father_graph, label_graph, file_name,
        #                    node_index, visited, feature_2, feature_3, feature_4, feature_5):
        results_b1 = down_traversal(child_graph, father_graph, label_graph, file_name,
                                                                    left_child_point, end_point)

    # bb2:
    if (right_child_point == end_point):
        results_b2 = [0, 0, 0, 0]
        pass
    else:
        results_b2 = down_traversal(child_graph, father_graph, label_graph, file_name,
                                                                    right_child_point, end_point)

    # return feature_2, feature_3, feature_4, feature_5
    return results_b1, results_b2


def parse(file_path, output_path, last_flag):
    print('进入parse')
    if(last_flag == -1):
        print('上次的parse函数返回值为-1！！！！！')
    global temp_df
    global output_df
    global class_name

    if file_path.endswith('.jimple'):
        flag = 0
    elif file_path.endswith('.dot'):
        flag = 1

    mode = 1
    # jimple->dot, mode=0, 表示继续延续之前的df分析, 分析dot
    if (last_flag == 0 and flag == 1):
        mode = 0
    # dot->jimple, mode=1, 将之前的temp_df append, 然后开一个新的空白temp_df, 分析jimple
    if (last_flag == 1 and flag == 0):
        mode = 1
    # 初始状态
    if (last_flag == 0 and flag == 0):
        mode = 1
    # dot->dot
    if (last_flag == 1 and flag == 1):
        mode = 0

    # mode=0, 分析dot; mode=1, 分析jimple
    if (mode == 0):
        print('进入mode0(分析dot)')
        with open(file_path, 'r') as f:
            str_dot_file = f.read()
            list_line_file = str_dot_file.split('\n')
            dot_file_name = file_path.split('/')[-1]
            class_name, method_name = split_class_method(dot_file_name)

            # 第一个点没有father，最后一个点没有child
            child_graph = dict()
            father_graph = dict()
            label_graph = dict()

            # start_points是SDK的那一行/还是if那一行呢 目前来看是SDK那一行 那么要找SDK_INT的值是多少的话就要在下一个节点了
            # end_points是merge_point
            # 全图的起始点和终止点很好找直接就是数据结构起始和终止点，跟这里的start和end_point无关
            # start和end_points的对应下标表示是同一组
            possible_start_points = []
            # flag = 0
            # 开始搜集点的标志，flag=1，有SDK点，才记录graph，否则不对该文件进行处理
            # 2020.4.27 直接把所有图开始啊
            # if (r'android.os.Build$VERSION.SDK_INT' in str_dot_file):
            #     flag = 1
            #
            # if (flag == 0):
            #     pass
            # 构建father_graph和child_graph
            if (1):
                for i in range(len(list_line_file)):
                    if ('android.os.Build' in list_line_file[i] and 'SDK_INT' in list_line_file[i]):
                        print(list_line_file[i])
                        # 找start_points
                        digits = re.findall('\d+', list_line_file[i])
                        if (digits != []):
                            # 现在加进来的start_point可能有假的，后面要给他检查一遍
                            possible_start_points.append(str(int(digits[0]) + 1))  # 注意因为是下一个点所以要加1
                    if (flag == 0):
                        continue
                    # 定义边
                    if (re.findall('"\d+"->"\d+";', list_line_file[i]) != []):
                        digits = re.findall('\d+', list_line_file[i])
                        if digits == []:
                            continue
                        if(len(digits) != 2):
                            continue
                        start, end = digits[0], digits[1]
                        start = str(start)
                        end = str(end)
                        if (start in child_graph):
                            if (child_graph[start]) == '':
                                child_graph[start] += end
                            else:
                                child_graph[start] += ('#' + end)

                        if (end in father_graph):
                            if (father_graph[end] == ''):
                                father_graph[end] += start
                            else:
                                father_graph[end] += ('#' + start)
                    # 定义点
                    elif (list_line_file[i].find('label') != -1):
                        digits = re.findall('\d+', list_line_file[i])
                        if digits == []:
                            continue

                        digit = digits[0]
                        digit = str(digit)

                        # 这里似乎不用了 因为前面已经找了start_point了
                        # 找start_point
                        # if (start_point == '-1' and 'if' in list_line_file[i]):
                        #     start_point = digit

                        # 数字全部采用string类型，子节点用#分隔
                        # 找子节点舒服，找父节点稍微麻烦
                        child_graph[digit] = ''
                        descriptions = re.findall('\[([\s\S]*)\]', list_line_file[i])
                        if descriptions == []:
                            continue
                        description = descriptions[0]
                        label_graph[digit] = description

                        digit_father = digits[0]
                        digit_father = str(digit_father)
                        father_graph[digit_father] = ''

                print('可能有的start_points的为: ', end='')
                print(possible_start_points)
                # 清理那种没有两个子节点的start_points
                # 因为每次pop之后会影响for循环的下标的问题，所以加个while循环
                start_points = []
                for i in range(len(possible_start_points)):
                    children = child_graph[possible_start_points[i]].split('#')
                    print('结点' + possible_start_points[i] + '的children为: ', end='')
                    print(children)
                    if(len(children) == 2):
                        start_points.append(possible_start_points[i])


                print('整理后的start_points为：', end='')
                print(start_points)
                # 对每一个start_point都要找到它的end_point、left/right_point，然后找到一个结果输出
                for start_point in start_points:
                    print('进入对每个start_point的循环')

                    sdk_int = -1
                    end_point = '-1'
                    statement = label_graph[start_point]
                    statement_List = re.findall('label=".*"', statement)
                    # 没有找到label语句（可能是表明edge语句），所以继续递归
                    if (statement_List == []):
                        pass
                    else:
                        statement_label = statement_List[0][7:-1]

                    digits = re.findall(r'[><!=]=? \d+', statement_label)
                    equals = re.findall(r'[><!=]=? ', statement_label)
                    digit = digits[0]
                    digits = re.findall(r'\d+', digit)
                    digit = digits[0]
                    equal = equals[0].replace(' ', '')
                    if (equal == '>='):
                        digit = int(digit) - 1
                        sdk_int = digit
                    elif (equal == '<='):
                        digit = int(digit) + 1
                        sdk_int = -digit
                    elif (equal == '<'):
                        digit = int(digit)
                        sdk_int = -digit
                    elif (equal == '>'):
                        digit = int(digit)
                        sdk_int = digit
                    elif (equal == '=='):
                        digit = int(digit)
                        sdk_int = '*' + str(digit)
                    elif (equal == '!='):
                        digit = int(digit)
                        sdk_int = '#' + str(digit)

                    try:
                        if (start_point != '-1'):
                            points = child_graph[start_point].split('#')
                    except KeyError:
                        return -1
                    # 这两个点指的是start_point的左右子节点
                    left_child_point = points[0]
                    right_child_point = points[1]
                    # 情况1: 汇合点
                    possible_end_points = []
                    for key in father_graph:
                        match_List = re.findall('#', father_graph[key])
                        if (len(match_List) == 1):
                            possible_end_points.append(key)
                    if (left_child_point in possible_end_points):
                        end_point = left_child_point
                    if (right_child_point in possible_end_points):
                        end_point = right_child_point
                    # 从possible_end_points中找出真正的end_point
                    print('可能的end_points为: ', end='')
                    print(possible_end_points)
                    if (end_point == '-1' and possible_end_points != []):
                        for item in possible_end_points:
                            fathers = father_graph[item].split('#')
                            case_1 = find_father(father_graph, fathers[0], left_child_point, start_point) and find_father(
                                father_graph,
                                fathers[1],
                                right_child_point,
                                start_point)
                            case_2 = find_father(father_graph, fathers[0], right_child_point, start_point) and find_father(
                                father_graph,
                                fathers[1],
                                left_child_point,
                                start_point)
                            if (case_1 or case_2):
                                end_point = item
                                break

                    print('实际找出来的end_point为: ', end='')
                    print(end_point)
                    # 情况2: 两个return点，暂时还没写，思路是用对应label中是否有return来判断，需要先建立存储label的数据结构
                    if (possible_end_points == []):
                        # 正常情况是return flag，-1表示没有找到对应结构
                        return -1
                    # print("此时start_point和end_point都找到了")
                    # print(left_child_point)
                    # print(right_child_point)
                    # print(start_point)
                    # print(possible_end_points)
                    # print(end_point)
                    #
                    # print(father_graph)
                    # print(child_graph)
                    #
                    # # 特征2、3、4、5、6
                    # print(label_graph)

                    # 此时start_point和end_point都找到了
                    # 特征2、3、4、5、6
                    # f[0-3] = f2\f3\f4\f5，每个元素又是一个二元的list
                    print('开始find_features_1')
                    f = find_features_1(father_graph, child_graph, label_graph, start_point, end_point, left_child_point,
                                    right_child_point, file_path)
                    print('find_features_1的返回值为', end='')
                    print(f)
                    # append两个temp_df
                    # for branch 1:
                    temp_df = pd.DataFrame()
                    temp_df['APK_NAME'] = [apk_name]
                    temp_df['SDK_INT'] = [sdk_int]
                    temp_df['CLASS_NAME'] = [class_name]
                    temp_df['METHOD_NAME'] = [method_name]
                    temp_df['LOC'] = [f[0][0]]
                    temp_df['has_Android_API_call'] = [f[0][1]]
                    temp_df['has_Android_API_arg'] = [f[0][2]]
                    temp_df['number_of_Android_API_calls'] = [f[0][3]]
                    output_df = output_df.append(temp_df)
                    print('branch1的temp_df为', end='')
                    print(temp_df)
                    # for branch 2:
                    temp_df = pd.DataFrame()
                    temp_df['APK_NAME'] = [apk_name]
                    temp_df['SDK_INT'] = [sdk_int]
                    temp_df['CLASS_NAME'] = [class_name]
                    temp_df['METHOD_NAME'] = [method_name]
                    temp_df['LOC'] = [f[1][0]]
                    temp_df['has_Android_API_call'] = [f[1][1]]
                    temp_df['has_Android_API_arg'] = [f[1][2]]
                    temp_df['number_of_Android_API_calls'] = [f[1][3]]
                    output_df = output_df.append(temp_df)
                    print('branch2的temp_df为', end='')
                    print(temp_df)

        # flag = 1
        return 1

    # mode = 1, 分析jimple
    if (mode == 1):
        print('进入mode1(分析jimple)')

        # 清空temp_df
        # if (not temp_df.empty):
        #     output_df.append(temp_df)
        # temp_df = pd.DataFrame()

        # temp_df['APK_NAME'] = [apk_name]

        # 下面这一段先注释了 不在jimple里面找SDK_INT版本号了

        # with open(file_path, 'r') as f:
        #     # 这个jimple_file需要保留到分析dot的时候也要用，在分析dot时可以用str_jimple_file这个变量
        #     str_jimple_file = f.read()
        #     list_line_file = str_jimple_file.split('\n')
        #
        #     # 清除list中的空元素（即代码中的空行）
        #     while '' in list_line_file:
        #         list_line_file.remove('')
        #
        #     for i in range(len(list_line_file)):
        #         if 'android.os.Build' in list_line_file[i] and 'SDK_INT' in list_line_file[i]:
        #             if 'if' in list_line_file[i + 1]:
        #                 # 特征1：SDK_INT
        #                 # print(list_line_file[i])
        #                 # print(list_line_file[i+1])
        #                 digits = re.findall(r'[><!=]=? \d+', list_line_file[i + 1])
        #                 equals = re.findall(r'[><!=]=? ', list_line_file[i + 1])
        #                 digit = digits[0]
        #                 digits = re.findall(r'\d+', digit)
        #                 digit = digits[0]
        #                 equal = equals[0].replace(' ', '')
        #                 print(digit)
        #                 print(equal)
        #                 if (equal == '>='):
        #                     digit = int(digit) - 1
        #                     temp_df['SDK_INT'] = [digit]
        #                 elif (equal == '<='):
        #                     digit = int(digit) + 1
        #                     temp_df['SDK_INT'] = [-digit]
        #                 elif (equal == '<'):
        #                     digit = int(digit)
        #                     temp_df['SDK_INT'] = [-digit]
        #                 elif (equal == '>'):
        #                     digit = int(digit)
        #                     temp_df['SDK_INT'] = [digit]
        #                 elif (equal == '=='):
        #                     digit = int(digit)
        #                     temp_df['SDK_INT'] = ['*' + str(digit)]
        #                 elif (equal == '!='):
        #                     digit = int(digit)
        #                     temp_df['SDK_INT'] = ['#' + str(digit)]
        #                 # temp_df['CLASS_NAME'] = [file_path.replace('.jimple', '').split('/')[-1]]
        #                 # class_name = file_path.replace('.jimple', '').split('/')[-1]
        # # flag = 0

        return 0


# 分离一个文件名中class部分和method部分
def split_class_method(string):
    string = str(string)

    if ('.dot' in string):
        pos = string.find('<')

        # 处理那种名字里不带<的
        if (pos == -1):
            # !!!!!这里找void是有问题的，除非你后面补全所有返回值类型

            pos = string.find('void') - 1
            left_string = string[:pos]
            right_srting = string.replace('.dot', '')[pos:]
            if ('MainActivity' in string):
                pass
                # print('我进入了')
                # print(string)
                # print(left_string)
                # print(right_srting)
            return left_string, right_srting

        counter = 0
        while (1):
            pos -= 1
            if (string[pos] == '.'):
                counter += 1
                if (counter == 2):
                    return string[:pos], string.replace('.dot', '')[pos:]
    else:
        return string.replace('.jimple', ''), ''


# 哎哟我真的服了，这个函数弄了半天，原来必须要返回1 -1这些，不能写成True False
def cmp_func(str1, str2):
    str1_class, str1_method = split_class_method(str1)
    str2_class, str2_method = split_class_method(str2)

    if (str1_class == str2_class):
        if (str2_method <= str2_method):
            return 1
        else:
            return -1
    elif (str1_class <= str2_class):
        return 1
    else:
        return -1


# 提取特征
def traverse(f):
    fs = os.listdir(f)

    # 自定义排序
    fs = sorted(fs, key=cmp_to_key(cmp_func))

    for item in fs:
        if (item.startswith('android')):
            continue
        else:
            print(item)

    first_flag = 0
    for f1 in fs:
        tmp_path = os.path.join(f, f1)
        if not os.path.isdir(tmp_path):
            # 抛弃android和androidx的文件 没有分析意义
            # 注意要android.开头或androidx.开头 不能用in 否则其他的也没了
            # startswith("android")已经包含了androidx
            file_name_list = tmp_path.split('/')
            file_name = file_name_list[-1]
            if (file_name.startswith('android')):
                # print(file_name, end='')
                # print('开头为android 不分析')
                continue

            # 第一次是0 后面是last_flag
            if(first_flag == 0):
                first_flag = 1
                print('正在解析文件1111: %s' % tmp_path)
                last_flag = parse(tmp_path, Csv_Output_DIR, 0)
            else:
                print('正在解析文件2222: %s' % tmp_path)
                last_flag = parse(tmp_path, Csv_Output_DIR, last_flag)


        else:
            # print('当前文件夹：%s' % tmp_path)
            file_name_list = tmp_path.split('/')
            file_name = file_name_list[-1]
            if (file_name.startswith('android')):
                print('开头为android 不分析')
                continue
            traverse(tmp_path)


if __name__ == '__main__':
    global APK_name

    FILE_DIR = '/home/soot_test'
    APK_DIR = FILE_DIR + '/APP'
    Soot_Output_DIR = FILE_DIR + '/MySootOutput'
    Csv_Output_DIR = FILE_DIR + '/OutputCsv'

    # start timer
    start_time = time.time()

    # search apk files
    FILES = os.listdir(APK_DIR)
    APK_FILES = []
    FILES = list(FILES)

    for i in range(len(FILES)):
        if (FILES[i][-4:] == ".apk"):
            APK_FILES.append(FILES[i])

    # loop 1: ith apk file
    # traverse: ith JIMPLE/DOT file
    FOLDERS = []
    JIMPLE_FILES = []
    DOT_FILES = []

    # delete old soot_output file
    if os.path.exists(FILE_DIR + '/MySootOutput'):
        child = subprocess.Popen('rm -rf ' + Soot_Output_DIR + '/*', shell=True)
        print("delete in process...")
        child.wait()
        print("delete succeed!")
        child.kill()

    # delete old csv_output file
    if os.path.exists(Csv_Output_DIR):
        child = subprocess.Popen('rm -rf ' + Csv_Output_DIR + '/*', shell=True)
        print("delete in process...")
        child.wait()
        print("delete succeed!")
        child.kill()

    # 对每个APK文件
    for i in range(len(APK_FILES)):
        apk_name = APK_FILES[i].replace('.apk', '')

        # 运行sh脚本(soot)
        print('cd ' + FILE_DIR + ' ;' + './runSootOnApktoDot.sh ' + APK_FILES[i])
        child = subprocess.Popen('cd ' + FILE_DIR + ' ;' + './runSootOnApktoDot.sh ' + APK_FILES[i], shell=True)
        print("soot in process...")
        child.wait()
        print("soot succeed!")
        child.kill()

        output_path = FILE_DIR + '/OutputCsv'

        # 遍历，保证jimple和dot次序的情况下搜集特征
        print('parsing...')
        traverse(Soot_Output_DIR)
        print('parse succeed!')

        # 输出csv
        print('output csv...')
        order = ['APK_NAME', 'CLASS_NAME', 'METHOD_NAME', 'SDK_INT', 'LOC', 'has_Android_API_call',
                 'has_Android_API_arg', 'number_of_Android_API_calls']
        # key error???
        # output_df = output_df[order]
        output_df.to_csv(output_path + '/' + apk_name + '.csv', encoding='utf-8', index=0)
        # to_csv之后要把output_df清空
        output_df = pd.DataFrame()
        print('output csv succeed!')

        # 删除上一个APK生成的文件(soot文件)
        # delete old soot_output file
        if os.path.exists(FILE_DIR + '/MySootOutput'):
            child = subprocess.Popen('rm -rf ' + Soot_Output_DIR + '/*', shell=True)
            print("delete soot_output in process...")
            child.wait()
            print("delete soot_output succeed!")
            child.kill()


    # end timer
    end_time = time.time()
    seconds = round(end_time - start_time, 0)
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    print("程序用时: ", end='')
    print("%02d:%02d:%02d" % (h, m, s))
