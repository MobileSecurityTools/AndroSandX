import objects_ASX
import mongodb_ASX
import sys
from util.color import *
import numpy
from sklearn import svm
from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.cross_validation import cross_val_score
from sklearn.metrics import precision_score, precision_recall_fscore_support
import pymongo

features = []
target = []
target_int = []
sample_set = []
sample_set_target = []
predicted_result = []
sample_set_ticket_id = []

svm_classifier = svm.SVC(gamma=0.001, C=100)
random_forest_classifier = RandomForestClassifier(n_estimators=500)
random_forest_regression = RandomForestRegressor(n_estimators=500)


def create_feature_input():
    mdb = mongodb_ASX.my_mdb()
    global features
    global target
    global target_int
    global sample_set
    global sample_set_target
    global sample_set_ticket_id

    mal_temp_fe = 0
    bing_temp_fe = 0




    # malware_total_feature = objects_ASX.ticket(None).ai_feature
    # benign_total_feature = objects_ASX.ticket(None).ai_feature

    mdb.cl_analysis_tickets.find().batch_size(10)
    tickets = mdb.cl_analysis_tickets.find({"droidmon_exists":1})
    count1 = 0
    for ticket in tickets:
        ticket = objects_ASX.ticket(ticket)
        # features.append(ticket.ai_feature)


        ##--------------- Just to print ai feature header names
        # if count1 == 0:
        #     for each in ticket.ai_feature:
        #         print "%s,"%each
        # exit()
        ##--------------- end of printing feature headers

        temp = []
        count = 0
        # if mal_temp_fe == 0 and ticket.ai_decision["analysis_conclusion"] == "malware":
        #     malware_total_feature = ticket.ai_feature
        #     mal_temp_fe +=1

        if ticket.ai_decision["analysis_conclusion"] == "malware":
            mal_temp_fe += 1

        # if bing_temp_fe == 0 and ticket.ai_decision["analysis_conclusion"] == "benign":
        #     benign_total_feature = ticket.ai_feature
        #     bing_temp_fe +=1

        if ticket.ai_decision["analysis_conclusion"] == "benign":
            bing_temp_fe += 1

        for each in ticket.ai_feature:
            ticket.ai_feature[each] = float(ticket.ai_feature[each])
            temp.append(ticket.ai_feature[each])

            # if ticket.ai_decision["analysis_conclusion"] == "malware":
            #     malware_total_feature[each] = malware_total_feature[each] + ticket.ai_feature[each]

            # if ticket.ai_decision["analysis_conclusion"] == "benign":
            #     benign_total_feature[each] = benign_total_feature[each] + ticket.ai_feature[each]

            # features.append(ticket.ai_feature[each])
            # print type(ticket.ai_feature[each])
            # if type(ticket.ai_feature[each]) != float:
            #     print red(ticket.ticket_id)
            #     # exit()
            count += 1

        # print temp

        #-----------------
        #print "Ticket_id: %s :: count :: %s"%(ticket.ticket_id,count)
        #print "Type: %s" % (ticket.ai_decision["analysis_conclusion"])
        #print count1
        # -----------------


        # target.append(ticket.ai_decision["analysis_conclusion"])

        if ticket.ai_decision["analysis_conclusion"] == "malware":
            target_int.append(1)
            # if count1 < 10 or count1 > 4772:
            #     sample_set_target.append(1)
        if ticket.ai_decision["analysis_conclusion"] == "benign":
            target_int.append(0)
            # if count1 < 10 or count1 > 4772:
            #     sample_set_target.append(0)

        if ticket.ai_decision["analysis_conclusion"] == "analyze_m":
            sample_set_target.append(1)
        if ticket.ai_decision["analysis_conclusion"] == "analyze_b":
            sample_set_target.append(0)

        if ticket.ai_decision["analysis_conclusion"] in ('malware','benign'):
            features.append(temp)
        elif ticket.ai_decision["analysis_conclusion"] in ('analyze_m','analyze_b'):
            sample_set.append(temp)
            sample_set_ticket_id.append(ticket.ticket_id)
        else:
            print "Error"
            exit()
        # if count1 < 10 or count1 > 4772:
        #     sample_set.append(temp)
        count1 += 1
    features = numpy.array(features,dtype=float)
    sample_set = numpy.array(sample_set,dtype=float)
    # target = numpy.array(target)
    target_int = numpy.array(target_int)
    sample_set_target = numpy.array(sample_set_target)
    # print features
    # print type(features)
    # print target
    # print type(target)

    print "Total Malware: %s"%(mal_temp_fe-1)
    # print red(malware_total_feature)
    print "====================================================================================="
    print "Total Bening: %s"%(bing_temp_fe-1)
    # print green(benign_total_feature)

def save_classifier():
    joblib.dump(svm_classifier, "svm_classifier_model.pkl")

def restore_classifier():
    svm_classifier = joblib.load("svm_classifier_model.pkl")

def save_csv():
    numpy.savetxt("trainig_data_features.csv",features,delimiter=",")
    numpy.savetxt("trainig_data_target_int.csv",target_int,delimiter=",")


    numpy.savetxt("trainig_data_sample_set.csv",sample_set,delimiter=",")
    numpy.savetxt("trainig_data_sample_set_target.csv",sample_set_target,delimiter=",")

    print "Files saved to CSV format :: \ntrainig_data_features.csv\ntrainig_data_target.csv\ntrainig_data_sample_set.csv\nrainig_data_sample_set_target\n"

def create_ai_model():

    #----SVM start
    print "==================SVM==================="
    print svm_classifier.fit(features,target_int)

    # ----SVM end


    #---- Random Forest start
    print "==================Random_forest==================="
    print " Classification : "
    print random_forest_classifier.fit(features,target_int)
    score = cross_val_score(random_forest_classifier, features, target_int)
    print "cross_val_score"
    print score.mean()

    print "Regression : "
    print random_forest_regression.fit(features,target_int)
    score = cross_val_score(random_forest_regression,features,target_int)
    print "cross_val_score"
    print score.mean()

    # ---- Random Forest end

    pass


def predict():
    global predicted_result
    print "Sample set length : %s" % (len(sample_set))

    print "+++++++SVM PREDICT+++++++"
    print svm_classifier.predict(sample_set)

    # for each in sample_set:
    #     print each


    # print random_forest_classifier.predict(features[:10])
    print "+++++++RandomForest Classification PREDICT+++++++"
    predicted_result = random_forest_classifier.predict(sample_set)
    print predicted_result

    print "+++++++RandomForest Regression PREDICT+++++++"
    predictd_result_rdmf_regression = random_forest_regression.predict(sample_set)
    print predictd_result_rdmf_regression

def score():
    print "+++++++++++++++++++++++++Score++++++++++++++++++++++"
    print "+++++++SVM score+++++++"
    print svm_classifier.score(sample_set,sample_set_target)

    print "+++++++RandomForest classification PREDICT+++++++"
    print random_forest_classifier.score(sample_set,sample_set_target)

    print "+++++Rnadom forest regression +++++"
    print random_forest_regression.score(sample_set,sample_set_target)

    print "+++++++ precision score +++++++"
    precision, recall, fbeta_score, support = precision_recall_fscore_support(sample_set_target,predicted_result,average=None)
    print "Precision :%s"%precision
    print "Recall :%s"%recall
    print "fbeta_score :%s"%fbeta_score
    print "support :%s"%support







if __name__ == "__main__":


    #ai_decision.analysis_conclusion : malware , benign , analyze_m , analyze_b

    if len(sys.argv) != 2 :
        print red("Error in the input!!!")
    if sys.argv[1] == "training":
        create_feature_input()
    else:
        exit()

    print "++++++"
    print "featur len"
    print len(features)
    print features.shape

    print "target len"
    print len(target_int)
    print target_int.shape

    print "sample set len"
    print len(sample_set)
    print sample_set.shape

    print "sample target len"
    print len(sample_set_target)
    print sample_set_target.shape

    print "\n==================== Building classifir ================================"
    create_ai_model()

    print "\n==================== Predicting ================================"
    predict()

    print "\n==================== Actual Sample target Set ================================"

    print sample_set_target


    mongodb_client = pymongo.MongoClient("192.168.0.105",27017)
    ticket_collection = mongodb_client.asx_core.analysis_tickets



    print "\n==================== Sample target Set ticket IDs================================"
    for each in range(0,len(predicted_result)):
        print "Ticket_id :: %s| Hash :: %s |Prediction :: %s |  Actual val :: %s"%(sample_set_ticket_id[each],ticket_collection.find_one({"ticket_id":sample_set_ticket_id[each]},{"hash_sha256":1})["hash_sha256"], predicted_result[each],sample_set_target[each])


    print "\n==================== Scoring ================================"
    score()

    save_csv()

    print  random_forest_classifier.feature_importances_