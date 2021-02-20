import glob
import numpy as np
from sklearn.model_selection import train_test_split
import math

#zero_dic은 0번 폴더, 즉 정상파일 샘플에서 각각의 txt파일에 대해 API당 TF값을
#dictionary로 나타냈습니다. 예를 들어 첫번째 txt파일에서 A라는 API의 TF값이
#0.7이라면 zero_dic[0] = {'A' : 0.7, .....} 처럼 표현했습니다.
#one_dic은 1번 폴더, 즉 악성파일 샘플에서 동일하게 저장했습니다.

#train_total과 test_total은 각각 train할 txt파일의 총 개수, test할 txt파일의
#총 개수를 저장했습니다.

#train_dic은 train파일 중 해당 API가 나오는 파일의 수를 저장했습니다.
#예를 들어 A라는 API가 총 1000개의 파일 중 300개의 파일에 존재했다면
#train_dic = {'A' : 300 , ......} 처럼 표현했습니다.
#test_dic은 test파일들에 대해 동일하게 저장했습니다.

zero_dic = []
one_dic = []
train_dic = {}
train_total = 0
test_dic = {}
test_total = 0


#API 폴더의 0폴더 안에 있는 정상파일들을 위에서 설명한 것처럼 zero_dic에
#각 API의 TF값을 dictonary 형태로 저장했습니다. 처음에 dic이라는
#빈 dictionary를 선언해 주었습니다. 그 이후 total이라는 변수를 선언해 주었는데
#해당 txt파일에서 등장하는 총 API의 개수를 저장합니다. 해당 txt파일에 등장하는
#API의 TF값을 TF = log( 1 + w / d) 식을 이용해 구해줍니다.

path = glob.glob("API/0/*.txt")

for filename in path:
    f = open(filename, 'r')
    dic = {}
    total = 0
    while True:
        line = f.readline()
        if not line:
            break
        line = line[:-1]
        if line in dic:
            tmp = dic[line]
            dic[line] = tmp + 1
        else:
            dic[line] = 1
        total += 1

    for i in dic:
        tmp = dic[i]
        tmp /= total
        tmp += 1
        tmp = math.log(tmp)
        dic[i] = tmp
    zero_dic.append(dic)
    f.close()


#1번 폴더의 악성파일들에 대해서도 똑같이 one_dic에 처리해줍니다.
    
path = glob.glob("API/1/*.txt")

for filename in path:
    f = open(filename, 'r')
    dic = {}
    total = 0
    while True:
        line = f.readline()
        if not line:
            break
        line = line[:-1]
        if line in dic:
            tmp = dic[line]
            dic[line] = tmp + 1
        else:
            dic[line] = 1
        total += 1

    for i in dic:
        tmp = dic[i]
        tmp /= total
        tmp += 1
        tmp = math.log(tmp)
        dic[i] = tmp
    one_dic.append(dic)
    f.close()

#악성파일, 정상파일 각각을 train set, test set으로 나누어줍니다.
#X는 정상파일들을, y는 악성파일들을 나타내고 악성파일은 train : test = 9 : 1로,
#정상파일은 train : test = 1 : 1로 나누어주었습니다.

x = list(range(1716))
y = list(range(4994))

x_train, x_test = train_test_split(x, test_size=0.5)
y_train, y_test = train_test_split(y, test_size=0.1)

#위에서 언급했듯이 train에서 쓰일 txt파일의 총 개수를 train_total에,
#test는 test_total에 저장해 주었습니다. train_dic은 train파일 중
#해당 API가 나오는 파일의 수를 저장했습니다. 예를 들어 A라는 API가
#총 1000개의 파일 중 300개의 파일에 존재했다면 train_dic = {'A' : 300 , ......}
#처럼 표현했습니다. test_dic은 test파일들에 대해 동일하게 저장했습니다.

for idx in x_train:
    for i in zero_dic[idx]:
        if i in train_dic:
            tmp = train_dic[i]
            train_dic[i] = tmp+1
        else:
            train_dic[i] = 1
    train_total += 1

for idx in x_test:
    for i in zero_dic[idx]:
        if i in test_dic:
            tmp = test_dic[i]
            test_dic[i] = tmp+1
        else:
            test_dic[i] = 1
    test_total += 1

for idx in y_train:
    for i in one_dic[idx]:
        if i in train_dic:
            tmp = train_dic[i]
            train_dic[i] = tmp+1
        else:
            train_dic[i] = 1
    train_total += 1

for idx in y_test:
    for i in one_dic[idx]:
        if i in test_dic:
            tmp = test_dic[i]
            test_dic[i] = tmp+1
        else:
            test_dic[i] = 1
    test_total += 1

#Train_dic에 각 API마다 IDF값을 저장했습니다. IDF값은 N / n 식을 이용해
#구했습니다. 예를 들어 A라는 API가 총 900개의 파일 중 300개의 파일에 존재했다면
#IDF값은 900 / 300 = 3이 될거고, train_dic = {‘A’ : 3 , …}처럼 표현했습니다.
#Test_dic은 test파일들에 대해 동일하게 저장했습니다.

for i in train_dic:
    tmp = train_dic[i]
    tmp = train_total / tmp

    train_dic[i] = tmp

for i in test_dic:
    tmp = test_dic[i]
    tmp = test_total / tmp
    test_dic[i] = tmp

#Virus_list에는 해당 API가 들어가 있으면 악성파일로 판단되는 API들을 리스트로
#표현했습니다. 이 리스트에 추가하는 기준은 train 파일들에서 TF-IDF값을
#TF * IDF라고 하고 모든 train파일의 API에 대해 TF-IDF값의 평균을 구해서
#악성파일 train set에서 TF*IDF 값이 평균 이상이면서 정상파일 train set에
#들어가 있지 않은 API들을 선정했습니다.
#Train_cnt와 train_sum은 모든 train파일의 API의 TF-IDF값의 평균을 구하기 위해
#사용되었습니다.

virus_list = []

train_cnt = 0
train_sum = 0

#One_dic에는 악성파일에서 해당 txt파일의 API에 대한 TF-IDF값들을 저장했습니다.
#예를 들어 악성파일 중 첫번째 txt파일의 A라는 API의 TF값이 0.5이고,
#IDF값이 4라면 TF-IDF값은 0.5 * 4 = 2이므로, one_dic[0] = {‘A’ : 2 , …} 처럼
#저장했습니다. Zero_dic에 대해서도 똑같이 실행했습니다.
#이 과정을 수행하면서 train set의 전체 TF-IDF값의 평균을
#train_avg에 저장했습니다.

for idx in y_train:
    for i in one_dic[idx]:
        tmp = one_dic[idx][i]
        tmp *= train_dic[i]
        one_dic[idx][i] = tmp
        train_sum += tmp
        train_cnt+=1

for idx in x_train:
    for i in zero_dic[idx]:
        tmp = zero_dic[idx][i]
        tmp *= train_dic[i]
        zero_dic[idx][i] = tmp
        train_sum += tmp
        train_cnt+=1

for idx in x_test:
    for i in zero_dic[idx]:
        tmp = zero_dic[idx][i]
        tmp *= test_dic[i]
        zero_dic[idx][i] = tmp

for idx in y_test:
    for i in one_dic[idx]:
        tmp = one_dic[idx][i]
        tmp *= test_dic[i]
        one_dic[idx][i] = tmp

train_avg = train_sum / train_cnt

#앞에서 설명했듯이 악성파일 train set에서 TF*IDF 값이 평균 이상이면서 정상파일
#train set에 들어가 있지 않은 API들을 virus_list에 저장했습니다.
#이 virus_list에 존재하는 API를 가지고 있는 파일을 악성파일로 분류했습니다.

for idx in y_train:
    for i in one_dic[idx]:
        if train_avg < one_dic[idx][i] and i not in virus_list:
            virus_list.append(i)
for idx in x_train:
    for i in virus_list:
        if i in zero_dic[idx]:
            virus_list.remove(i)

#앞에서 말한 분류기준을 이용해 test_set에서 악성파일을 분류해냈습니다.
#Zero_total은 test에 사용되는 전체 정상파일의 수이고, zero_true는
#전체 정상파일 중 테스트 결과 정상파일로 분류된 파일의 수입니다.
#따라서 정상파일들에 대해서 이 테스트를 진행한 결과 정확도는
#100 * zero_true / zero_total 로 계산할 수 있습니다.
#악성파일에 대해서도 똑같이 실행해 보았습니다. 

zero_total = 0
one_total = 0
zero_true = 0
one_true = 0

for idx in x_test:
    chk = True
    for j in virus_list:
        if j in zero_dic[idx]:
            chk = False
    zero_total += 1
    if chk:
        zero_true += 1
                

for idx in y_test:
    chk = False
    for j in virus_list:
        if j in one_dic[idx]:
            chk = True
    one_total += 1
    if chk:
        one_true += 1

print("zero rate", 100 * zero_true / zero_total)
print("one rate", 100 * one_true / one_total)
        







